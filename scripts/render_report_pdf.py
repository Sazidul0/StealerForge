#!/usr/bin/env python3
"""Render a StealerForge CTI Markdown report (docs/AI-REPORT-GUIDE.md format) to a styled PDF.

The Markdown stays the source of truth for ti2dac; this script changes presentation only:
cover page with verdict tiles, citation chips, status pills, finding and action cards,
attack-flow step chains, an execution timeline, one card per ATT&CK behaviour, and page numbers.

Requirements: Python with `markdown` and `beautifulsoup4` (pip install markdown beautifulsoup4,
or a system python3 that already has them) and Google Chrome or Chromium for printing.

Usage:
  python3 -I scripts/render_report_pdf.py <report.md> [--out report.pdf] [--copy-to output/]
         [--family NAME] [--verdict Malicious] [--name FILE.pdf] [--keep-html]

Untrusted sample strings in the report are escaped (raw HTML is disabled) and the page is
printed under a Content-Security-Policy that blocks every network request.
"""
import argparse
import html
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import markdown
    from bs4 import BeautifulSoup, NavigableString
except ImportError as exc:  # pragma: no cover - environment dependent
    sys.exit(f'missing dependency ({exc.name}); install with: pip install markdown beautifulsoup4 '
             f'(or run with a system python3 that has them)')

TLP_COLOURS = {'CLEAR': ('#000', '#fff'), 'GREEN': ('#1e7a3e', '#fff'), 'AMBER': ('#c98a00', '#000'),
               'AMBER+STRICT': ('#c98a00', '#000'), 'RED': ('#a61b1b', '#fff')}
CHROMES = ('google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser')


def esc_lt(md_text):
    """Escape '<' outside code spans and fences: disables raw HTML and keeps placeholders like <random>."""
    out, fence = [], False
    for line in md_text.splitlines():
        if line.lstrip().startswith('```'):
            fence = not fence
            out.append(line)
            continue
        if fence:
            out.append(line)
            continue
        parts = line.split('`')
        for i in range(0, len(parts), 2):
            parts[i] = parts[i].replace('<', '&lt;')
        out.append('`'.join(parts))
    return '\n'.join(out)


def status_class(text):
    t = text.lower()
    if t.startswith(('observed', 'stolen')):
        return 'obs'
    if t.startswith(('capability', 'predicted')):
        return 'cap'
    if t.startswith('inferred'):
        return 'inf'
    if t.startswith(('not found', 'static', 'not checked')):
        return 'nf'
    if t.startswith('attempted'):
        return 'fail'
    return None


def build_html(src, family=None, verdict='Malicious'):
    lines = src.splitlines()
    title = lines[0].lstrip('# ').strip()
    short_title = title.replace(': threat intelligence report', '')
    first = next(i for i, l in enumerate(lines) if l.startswith('## '))
    tlp = next((l.split(':', 1)[1].strip() for l in lines[1:first] if l.startswith('TLP:')), 'CLEAR')
    meta_text = ' '.join(l for l in lines[1:first] if l.strip() and not l.startswith('TLP:'))
    meta = {m.group(1).strip(): m.group(2).strip()
            for m in re.finditer(r'\*\*([^*]+):\*\*\s*([^·*]+?)(?=\s*·|\s*\*\*|$)', meta_text)}
    run = re.search(r'StealerForge run (\S+?),', meta_text)
    family = family or short_title.split()[0]

    md = markdown.Markdown(extensions=['tables', 'fenced_code', 'sane_lists', 'toc'],
                           extension_configs={'toc': {'toc_depth': '2-2'}})
    body_html = md.convert(esc_lt('\n'.join(lines[first:])))
    soup = BeautifulSoup(body_html, 'html.parser')

    def new(tag, cls=None, text=None):
        t = soup.new_tag(tag)
        if cls:
            t['class'] = cls
        if text is not None:
            t.string = text
        return t

    def section(prefix):
        return next((h for h in soup.find_all('h2') if h.get_text().startswith(prefix)), None)

    def siblings_until(start, stop):
        out = []
        if start is None:
            return out
        for sib in start.next_siblings:
            if getattr(sib, 'name', None) in stop:
                break
            out.append(sib)
        return out

    # citation chips: [E0000022][A1] -> one small grey chip
    cite = re.compile(r'((?:\[(?:E\d{7}|A\d+)\])+)')
    for node in list(soup.find_all(string=cite)):
        if node.find_parent(['code', 'pre']):
            continue
        frag = []
        for part in cite.split(str(node)):
            if cite.fullmatch(part):
                ids = ' · '.join(re.findall(r'\[([^\]]+)\]', part))
                frag.append(f'<span class="cite">{ids}</span>')
            elif part:
                frag.append(html.escape(part))
        node.replace_with(BeautifulSoup(''.join(frag), 'html.parser'))

    # "(Observed, High)" style status and confidence pills in prose
    pill = re.compile(r'\((Observed(?: and Capability)?|Capability|Inferred|Attempted, failed)(?:, (High|Medium|Low))?\)')
    for node in list(soup.find_all(string=pill)):
        if node.find_parent(['code', 'pre']):
            continue

        def rep(m):
            out = f'<span class="pill {status_class(m.group(1))}">{m.group(1)}</span>'
            return out + (f'<span class="pill conf">{m.group(2)}</span>' if m.group(2) else '')
        node.replace_with(BeautifulSoup(pill.sub(rep, html.escape(str(node), quote=False)), 'html.parser'))

    # executive summary: at-a-glance table, bottom-line callout, finding cards, action cards
    subtitle = None
    h1 = section('1.')
    for el in siblings_until(h1, ['h2']):
        name = getattr(el, 'name', None)
        if name == 'table':
            head = el.find('th')
            if head and head.get_text(strip=True).lower() == 'at a glance':
                el['class'] = ['glance']
                for tr in el.find_all('tr')[1:]:
                    tds = tr.find_all('td')
                    if len(tds) == 2 and tds[0].get_text(strip=True).lower() == 'what it is':
                        subtitle = tds[1].get_text(' ', strip=True)
        if name != 'p':
            continue
        strong = el.find('strong')
        if strong and strong.get_text().startswith('Bottom line'):
            text = strong.get_text().split(':', 1)[-1].strip()
            box = new('div', ['callout'])
            box.append(new('div', ['callout-label'], 'Bottom line'))
            box.append(new('div', ['callout-text'], text[:1].upper() + text[1:]))
            el.replace_with(box)
        elif strong and strong.get_text() in ('Key findings', 'Priority actions'):
            el['class'] = ['subhead']
            ul = el.find_next_sibling('ul')
            if ul is None:
                continue
            if strong.get_text() == 'Key findings':
                ul['class'] = ['findings']
                for li in ul.find_all('li', recursive=False):
                    last = li.contents[-1] if li.contents else None
                    if isinstance(last, NavigableString) and last.strip() == '.':
                        last.extract()
            else:
                ul['class'] = ['actions']
                for li in ul.find_all('li', recursive=False):
                    key = li.find('strong')
                    li['class'] = ['act', key.get_text().rstrip(':').lower() if key else '']

    # how it works: numbered stage headings, attack-flow chains, execution timeline
    for h in [x for x in siblings_until(section('3.'), ['h2']) if getattr(x, 'name', None) == 'h3']:
        t = h.get_text()
        m = re.match(r'Stage (\d+): (.+)', t)
        if m:
            h.clear()
            h['class'] = ['stage']
            h.append(new('span', ['stage-no'], m.group(1)))
            h.append(NavigableString(m.group(2)))
        elif t == 'Attack flow' and h.find_next_sibling('pre'):
            pre = h.find_next_sibling('pre')
            flow = new('div', ['flow'])
            for i, row in enumerate(r for r in pre.get_text().splitlines() if r.strip()):
                line = new('div', ['flow-row'])
                line.append(new('div', ['flow-idx'], str(i + 1)))
                chain = new('div', ['flow-chain'])
                for j, step in enumerate(s.strip() for s in re.split(r'\s*->\s*', row.strip()) if s.strip()):
                    if j:
                        chain.append(new('span', ['arrow'], '→'))
                    chain.append(new('span', ['step'], step))
                line.append(chain)
                flow.append(line)
            pre.replace_with(flow)
        elif t == 'Execution flow' and h.find_next_sibling('ol'):
            ol = h.find_next_sibling('ol')
            tl = new('div', ['timeline'])
            for li in ol.find_all('li', recursive=False):
                inner = li.decode_contents()
                m2 = re.match(r'\s*(T\+[\d:]+(?: to T\+[\d:]+)?),\s*(.*)', inner, re.S)
                row = new('div', ['tl-row'])
                row.append(new('div', ['tl-time'], m2.group(1) if m2 else ''))
                body = new('div', ['tl-body'])
                body.append(BeautifulSoup(m2.group(2) if m2 else inner, 'html.parser'))
                row.append(body)
                tl.append(row)
            ol.replace_with(tl)

    # behaviours: one card per "### B<n>. Name (T<id>)"
    for h in [x for x in siblings_until(section('4.'), ['h2']) if getattr(x, 'name', None) == 'h3']:
        m = re.match(r'(B\d+)\. (.+) \((T\d{4}(?:\.\d{3})?)\)', h.get_text())
        if not m:
            continue
        card = new('div', ['bcard'])
        head = new('div', ['bhead'])
        for cls, text in (('bid', m.group(1)), ('bname', m.group(2)), ('tech', m.group(3))):
            head.append(new('span', [cls], text))
        card.append(head)
        parts = []
        for sib in list(h.next_siblings):
            if getattr(sib, 'name', None) in ('h2', 'h3'):
                break
            parts.append(sib)
        h.replace_with(card)
        for p in parts:
            p = p.extract()
            if getattr(p, 'name', None) != 'p':
                if str(p).strip():
                    card.append(p)
                continue
            txt = p.get_text()
            if txt.startswith('Tactic:'):
                mt = re.match(r'Tactic: (.+?)\. Status: (.+?)\. Confidence: (\w+)\.', txt)
                chips = new('div', ['bmeta'])
                if mt:
                    chips.append(new('span', ['chip', 'tactic'], mt.group(1)))
                    chips.append(new('span', ['pill', status_class(mt.group(2)) or 'obs'], mt.group(2)))
                    chips.append(new('span', ['pill', 'conf'], f'Confidence: {mt.group(3)}'))
                else:
                    chips.append(BeautifulSoup(p.decode_contents(), 'html.parser'))
                card.append(chips)
            elif txt.startswith('Telemetry:'):
                inner = p.decode_contents()
                mm = re.match(r'\s*<strong>Telemetry:</strong>\s*(.*?)\s*<strong>Detection opportunity:</strong>\s*(.*)',
                              inner, re.S)
                grid = new('div', ['bgrid'])
                if mm:
                    for label, value in (('Telemetry', mm.group(1)), ('Detection opportunity', mm.group(2))):
                        cell = new('div', ['bcell'])
                        cell.append(new('div', ['blabel'], label))
                        val = new('div')
                        val.append(BeautifulSoup(value, 'html.parser'))
                        cell.append(val)
                        grid.append(cell)
                else:
                    grid.append(BeautifulSoup(inner, 'html.parser'))
                card.append(grid)
            else:
                p['class'] = ['bproc']
                card.append(p)

    # tables: colour the status, observation, priority and actionability columns
    def tables(prefix):
        return [t for t in siblings_until(section(prefix), ['h2']) if getattr(t, 'name', None) == 'table']

    def col(table, header):
        row = table.find('tr')
        names = [th.get_text(strip=True) for th in row.find_all('th')] if row else []
        return names.index(header) if header in names else None

    def pill_cell(td, cls):
        if cls:
            txt = td.get_text(' ', strip=True)
            td.clear()
            td.append(new('span', ['pill'] + cls.split(), txt))

    for prefix, header in (('5.', 'Status'), ('6.', 'Status'), ('8.', 'Observed or predicted')):
        for t in tables(prefix):
            i = col(t, header)
            for tr in (t.find_all('tr')[1:] if i is not None else []):
                tds = tr.find_all('td')
                if i < len(tds):
                    pill_cell(tds[i], status_class(tds[i].get_text(strip=True)))
    for t in tables('9.'):
        i = col(t, 'Priority')
        for tr in (t.find_all('tr')[1:] if i is not None else []):
            td = tr.find_all('td')[i]
            pill_cell(td, f'prio {td.get_text(strip=True).lower()}')
    for t in tables('Indicators'):
        t['class'] = ['ioc']
        i, j = col(t, 'Actionability'), col(t, 'Observed or static')
        for tr in t.find_all('tr')[1:]:
            tds = tr.find_all('td')
            if i is not None and i < len(tds):
                v = tds[i].get_text(strip=True).lower()
                pill_cell(tds[i], 'block' if v.startswith('block') else 'hunt' if v.startswith('hunt') else 'ctx')
            if j is not None and j < len(tds):
                pill_cell(tds[j], status_class(tds[j].get_text(strip=True)))
            if len(tds) > 1:
                tds[1]['class'] = ['mono']

    # bold-only label paragraphs stay with what follows
    for p in soup.find_all('p'):
        kids = [k for k in p.contents if not (isinstance(k, NavigableString) and not k.strip())]
        if kids and getattr(kids[0], 'name', None) == 'strong' and 'subhead' not in p.get('class', []) and (
                len(kids) == 1 or (isinstance(kids[-1], NavigableString) and len(p.get_text()) < 70)):
            p['class'] = p.get('class', []) + ['label']

    # page breaks before the major parts; smaller type in appendices
    for h in soup.find_all('h2'):
        t = h.get_text()
        if re.match(r'(1|4)\. ', t) or t.startswith(('Indicators', 'Appendix')):
            h['class'] = h.get('class', []) + ['newpage']
    in_appendix = False
    for el in list(soup.children):
        if getattr(el, 'name', None) == 'h2' and el.get_text().startswith('Appendix'):
            in_appendix = True
        if in_appendix and getattr(el, 'name', None):
            el['class'] = el.get('class', []) + ['appx']

    tlp_bg, tlp_fg = TLP_COLOURS.get(tlp.upper(), TLP_COLOURS['CLEAR'])
    footer = f'{short_title}  ·  TLP:{tlp}'.replace('"', "'")
    sub = f'<p class="subtitle">{html.escape(subtitle)}</p>' if subtitle else ''
    cover = f'''
<section class="cover">
  <div class="cover-top"><span class="kicker">Threat intelligence report</span><span class="tlp">TLP:{html.escape(tlp)}</span></div>
  <h1>{html.escape(short_title)}</h1>{sub}
  <div class="verdict">
    <div><div class="vlabel">Verdict</div><div class="vval bad">{html.escape(verdict)}</div></div>
    <div><div class="vlabel">Family</div><div class="vval">{html.escape(family)}</div></div>
    <div><div class="vlabel">Confidence</div><div class="vval">{html.escape(meta.get('Overall confidence', ''))}</div></div>
    <div><div class="vlabel">Analysis date</div><div class="vval">{html.escape(meta.get('Analysis date', ''))}</div></div>
  </div>
  <dl class="cover-meta">
    <dt>SHA-256</dt><dd class="mono">{html.escape(meta.get('SHA-256', ''))}</dd>
    <dt>Status</dt><dd>{html.escape(meta.get('Analysis status', ''))}</dd>
    <dt>Prepared with</dt><dd>{html.escape(meta.get('Prepared with', ''))}</dd>
  </dl>
  <nav class="toc"><div class="toc-title">Contents</div>{md.toc}</nav>
  <div class="legend">
    <span class="pill obs">Observed</span> seen in the sandbox
    <span class="pill cap">Capability</span> present in code, not run
    <span class="pill inf">Inferred</span> reasoned
    <span class="cite">E0000000</span> evidence record
    <span class="cite">A1</span> analyst finding (Appendix E)
  </div>
</section>'''
    endnote = ('Rendered from the Markdown report, which remains the source of truth for ti2dac'
               + (f'. StealerForge run {html.escape(run.group(1))}.' if run else '.'))
    css = CSS.replace('__FOOTER__', footer).replace('__TLPBG__', tlp_bg).replace('__TLPFG__', tlp_fg)
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            f'<title>{html.escape(short_title)}</title><style>{css}</style></head><body>{cover}\n{soup}\n'
            f'<p class="endnote">{endnote}</p></body></html>'), short_title


CSS = r'''
@page { size: A4; margin: 18mm 16mm 18mm 16mm;
  @bottom-left { content: "__FOOTER__"; font: 7.5pt Inter, "Segoe UI", sans-serif; color: #8a94a3; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 7.5pt Inter, "Segoe UI", sans-serif; color: #8a94a3; } }
@page :first { @bottom-left { content: none; } @bottom-right { content: none; } }
:root { --ink:#1f2933; --muted:#616e7c; --soft:#8a94a3; --line:#e1e5ea; --bg:#f7f8fa; --accent:#a61b1b; --accent-soft:#fbeaea;
        --obs:#1e7a3e; --obs-bg:#e4f4e9; --cap:#8a5a00; --cap-bg:#fff3d9; --inf:#1f5fa8; --inf-bg:#e6effa; --nf:#5b6470; --nf-bg:#eef0f3; }
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { font-family: Inter, "Segoe UI", "Helvetica Neue", Arial, sans-serif; color: var(--ink); font-size: 9.4pt; line-height: 1.55; margin: 0; }
p { margin: 0 0 2.4mm; orphans: 3; widows: 3; }
ul, ol { margin: 0 0 2.4mm; padding-left: 5.5mm; } li { margin: 0 0 1.2mm; }
strong { font-weight: 600; }
code { font-family: "JetBrains Mono", "DejaVu Sans Mono", Consolas, monospace; font-size: 8.2pt; background: var(--bg); border: 1px solid var(--line);
       padding: 0 1mm; border-radius: 3px; overflow-wrap: anywhere; }
pre { background: var(--bg); border: 1px solid var(--line); border-left: 3px solid var(--soft); border-radius: 4px; padding: 3mm 3.5mm;
      white-space: pre-wrap; overflow-wrap: anywhere; margin: 2mm 0 3.5mm; font-size: 7.8pt; line-height: 1.45; }
pre code { background: none; border: 0; padding: 0; font-size: inherit; }
.mono { font-family: "JetBrains Mono", "DejaVu Sans Mono", Consolas, monospace; font-size: 7.8pt; overflow-wrap: anywhere; }
h2 { font-size: 15pt; font-weight: 700; letter-spacing: -.01em; margin: 0 0 4mm; padding-bottom: 2mm; border-bottom: 1px solid var(--line); page-break-after: avoid; }
h2::before { content: ""; display: inline-block; width: 3.2mm; height: 3.2mm; background: var(--accent); border-radius: 1px; margin-right: 2.5mm; vertical-align: .1mm; }
h2.newpage { page-break-before: always; } h2:not(.newpage) { margin-top: 9mm; }
h3 { font-size: 11pt; font-weight: 600; margin: 6mm 0 2.5mm; page-break-after: avoid; }
.cite { display: inline-block; font-size: 6.6pt; font-weight: 500; color: var(--soft); background: var(--bg); border: 1px solid var(--line);
        border-radius: 3px; padding: 0 1mm; line-height: 1.5; vertical-align: .3mm; white-space: nowrap; }
.pill { display: inline-block; font-size: 7.4pt; font-weight: 600; border-radius: 10px; padding: .2mm 2.2mm; line-height: 1.5; white-space: nowrap; margin-right: 1mm; }
.pill.obs { background: var(--obs-bg); color: var(--obs); } .pill.cap { background: var(--cap-bg); color: var(--cap); }
.pill.inf { background: var(--inf-bg); color: var(--inf); } .pill.nf { background: var(--nf-bg); color: var(--nf); }
.pill.fail, .pill.block { background: var(--accent-soft); color: var(--accent); } .pill.conf, .pill.ctx { background: var(--nf-bg); color: var(--nf); }
.pill.hunt { background: var(--cap-bg); color: var(--cap); }
.pill.prio.p1 { background: var(--accent); color: #fff; } .pill.prio.p2 { background: var(--cap-bg); color: var(--cap); } .pill.prio.p3 { background: var(--nf-bg); color: var(--nf); }
table { width: 100%; border-collapse: collapse; margin: 2mm 0 4mm; font-size: 8.1pt; line-height: 1.45; }
thead th { background: var(--bg); color: var(--muted); font-weight: 600; font-size: 7.4pt; text-transform: uppercase; letter-spacing: .04em; text-align: left; border-bottom: 1.5px solid var(--line); }
th, td { padding: 1.8mm 2mm; vertical-align: top; border-bottom: 1px solid var(--line); overflow-wrap: normal; word-break: normal; }
tr { page-break-inside: avoid; } td code { overflow-wrap: anywhere; }
.cover { page-break-after: always; }
.cover-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10mm; }
.kicker { font-size: 8pt; font-weight: 700; letter-spacing: .16em; text-transform: uppercase; color: var(--accent); }
.tlp { background: __TLPBG__; color: __TLPFG__; font-weight: 700; font-size: 8.5pt; letter-spacing: .06em; padding: 1mm 3mm; border-radius: 3px; }
.cover h1 { font-size: 26pt; line-height: 1.12; letter-spacing: -.02em; margin: 0 0 3mm; }
.subtitle { font-size: 11.5pt; color: var(--muted); margin-bottom: 8mm; }
.verdict { display: grid; grid-template-columns: repeat(4, 1fr); gap: 3mm; margin: 6mm 0 7mm; }
.verdict > div { background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 3mm 3.5mm; }
.vlabel { font-size: 7pt; text-transform: uppercase; letter-spacing: .08em; color: var(--soft); font-weight: 600; }
.vval { font-size: 12pt; font-weight: 700; margin-top: .8mm; } .vval.bad { color: var(--accent); }
.cover-meta { display: grid; grid-template-columns: 30mm 1fr; gap: 1.6mm 4mm; margin: 0 0 8mm; font-size: 8.6pt; }
.cover-meta dt { color: var(--soft); font-weight: 600; } .cover-meta dd { margin: 0; }
.toc { border-top: 1px solid var(--line); padding-top: 4mm; }
.toc-title { font-size: 7.5pt; text-transform: uppercase; letter-spacing: .1em; color: var(--soft); font-weight: 700; margin-bottom: 2mm; }
.toc ul { list-style: none; padding: 0; columns: 2; column-gap: 8mm; margin: 0; } .toc li { margin: 0 0 1.3mm; break-inside: avoid; }
.toc a { color: var(--ink); text-decoration: none; font-size: 9pt; }
.legend { margin-top: 8mm; padding-top: 3mm; border-top: 1px solid var(--line); font-size: 7.8pt; color: var(--muted); line-height: 2.1; }
.legend .pill, .legend .cite { margin-left: 2.5mm; }
table.glance { margin: 4mm 0 5mm; font-size: 8.8pt; } table.glance thead { display: none; }
table.glance td:first-child { width: 34mm; font-weight: 600; color: var(--muted); }
.callout { background: var(--accent-soft); border-left: 4px solid var(--accent); border-radius: 4px; padding: 3mm 4mm; margin: 4mm 0 5mm; page-break-inside: avoid; }
.callout-label { font-size: 7pt; font-weight: 700; text-transform: uppercase; letter-spacing: .1em; color: var(--accent); margin-bottom: .8mm; }
.callout-text { font-weight: 600; font-size: 10pt; line-height: 1.45; }
p.subhead { font-size: 7.6pt; text-transform: uppercase; letter-spacing: .1em; color: var(--soft); margin: 5mm 0 2mm; page-break-after: avoid; }
p.subhead strong { font-weight: 700; }
ul.findings { list-style: none; padding: 0; }
ul.findings li { border: 1px solid var(--line); border-left: 3px solid var(--ink); border-radius: 4px; padding: 2.2mm 3mm; margin-bottom: 2mm; page-break-inside: avoid; }
ul.actions { list-style: none; padding: 0; display: grid; grid-template-columns: repeat(3, 1fr); gap: 3mm; }
li.act { border-radius: 6px; padding: 3mm; margin: 0; font-size: 8.4pt; border-top: 4px solid var(--ink); background: var(--bg); }
li.act.block { border-color: var(--accent); } li.act.hunt { border-color: #c98a00; } li.act.reset { border-color: var(--inf); }
li.act > strong:first-child { display: block; font-size: 10pt; margin-bottom: 1mm; }
h3.stage { display: flex; align-items: center; gap: 2.5mm; }
.stage-no { display: inline-flex; align-items: center; justify-content: center; width: 6mm; height: 6mm; border-radius: 50%; background: var(--ink); color: #fff; font-size: 8pt; font-weight: 700; }
.flow { border: 1px solid var(--line); border-radius: 6px; padding: 3mm; margin: 2mm 0 4mm; page-break-inside: avoid; }
.flow-row { display: flex; gap: 3mm; align-items: flex-start; padding: 1.8mm 0; border-bottom: 1px dashed var(--line); } .flow-row:last-child { border-bottom: 0; }
.flow-idx { flex: 0 0 5.5mm; height: 5.5mm; border-radius: 50%; background: var(--accent); color: #fff; font-size: 7.5pt; font-weight: 700; display: flex; align-items: center; justify-content: center; margin-top: .4mm; }
.flow-chain { display: flex; flex-wrap: wrap; gap: 1.4mm; align-items: center; }
.step { background: var(--bg); border: 1px solid var(--line); border-radius: 4px; padding: .6mm 2mm; font-size: 7.9pt; } .arrow { color: var(--soft); font-size: 9pt; }
.timeline { border-left: 2px solid var(--line); margin: 2mm 0 4mm 2mm; }
.tl-row { display: flex; gap: 4mm; padding: 1.3mm 0 1.3mm 4mm; position: relative; page-break-inside: avoid; }
.tl-row::before { content: ""; position: absolute; left: -1.6mm; top: 2.6mm; width: 2.4mm; height: 2.4mm; border-radius: 50%; background: var(--accent); }
.tl-time { flex: 0 0 26mm; font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace; font-size: 7.8pt; color: var(--muted); padding-top: .3mm; }
.tl-body { flex: 1; font-size: 8.6pt; }
.bcard { border: 1px solid var(--line); border-radius: 6px; padding: 3mm 3.5mm 2mm; margin: 0 0 3.5mm; page-break-inside: avoid; }
.bhead { display: flex; align-items: baseline; gap: 2.5mm; margin-bottom: 1.6mm; }
.bid { font-weight: 700; color: #fff; background: var(--ink); border-radius: 3px; padding: 0 1.6mm; font-size: 8pt; }
.bname { font-weight: 650; font-size: 10.3pt; flex: 1; }
.tech { font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace; font-size: 7.6pt; color: var(--accent); border: 1px solid #e6b8b8; border-radius: 3px; padding: 0 1.4mm; }
.bmeta { margin-bottom: 2mm; }
.chip.tactic { display: inline-block; font-size: 7.4pt; font-weight: 600; border: 1px solid var(--line); border-radius: 10px; padding: .2mm 2.2mm; margin-right: 1mm; }
.bproc { margin-bottom: 2mm; }
.bgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 2.5mm; margin-bottom: 1mm; }
.bcell { background: var(--bg); border-radius: 4px; padding: 2mm 2.5mm; font-size: 8.1pt; }
.blabel { font-size: 6.8pt; text-transform: uppercase; letter-spacing: .08em; color: var(--soft); font-weight: 700; margin-bottom: .6mm; }
table.ioc { font-size: 7.6pt; } table.ioc td:nth-child(2) { width: 30%; }
.appx { font-size: 8.6pt; } h2.appx { font-size: 14pt; } table.appx { font-size: 7.6pt; }
p.label { page-break-after: avoid; margin-top: 3mm; }
.endnote { margin-top: 10mm; padding-top: 3mm; border-top: 1px solid var(--line); font-size: 7.6pt; color: var(--soft); }
'''


def find_chrome(explicit):
    if explicit:
        return explicit
    for name in CHROMES:
        path = shutil.which(name)
        if path:
            return path
    sys.exit('Chrome or Chromium not found; pass --chrome /path/to/chrome')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('report', type=Path)
    ap.add_argument('--out', type=Path, help='PDF path (default: next to the report, same name, .pdf)')
    ap.add_argument('--copy-to', type=Path, help='also copy the PDF into this folder, e.g. output/')
    ap.add_argument('--name', help='file name for --copy-to (default: <title>_Threat_Intel_Report.pdf)')
    ap.add_argument('--family', help='family shown on the cover (default: first word of the title)')
    ap.add_argument('--verdict', default='Malicious', help='verdict shown on the cover')
    ap.add_argument('--chrome', help='path to Chrome or Chromium')
    ap.add_argument('--keep-html', action='store_true', help='keep the intermediate HTML next to the PDF')
    args = ap.parse_args()

    page, short_title = build_html(args.report.read_text(encoding='utf-8'), args.family, args.verdict)
    out = (args.out or args.report.with_suffix('.pdf')).resolve()
    with tempfile.TemporaryDirectory() as tmp:
        html_path = Path(tmp) / 'report.html'
        html_path.write_text(page, encoding='utf-8')
        cmd = [find_chrome(args.chrome), '--headless=new', '--disable-gpu', '--no-pdf-header-footer',
               f'--user-data-dir={tmp}/profile', f'--print-to-pdf={out}', html_path.as_uri()]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0 or not out.exists():
            sys.exit(f'Chrome failed ({proc.returncode}): {proc.stderr.strip()[-400:]}')
        if args.keep_html:
            shutil.copy(html_path, out.with_suffix('.html'))
    print(f'PDF: {out}')
    if args.copy_to:
        args.copy_to.mkdir(parents=True, exist_ok=True)
        name = args.name or re.sub(r'[^A-Za-z0-9]+', '_', short_title).strip('_') + '_Threat_Intel_Report.pdf'
        dest = args.copy_to / name
        shutil.copy(out, dest)
        print(f'Copy: {dest.resolve()}')


if __name__ == '__main__':
    main()
