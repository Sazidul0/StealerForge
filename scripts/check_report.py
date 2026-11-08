#!/usr/bin/env python3
"""Check an agent-written StealerForge CTI report against docs/AI-REPORT-GUIDE.md.

Usage:
    python3 -I scripts/check_report.py REPORT.md [--evidence path/to/evidence.json]

Standard library only. Exit code 0 = no errors (warnings may remain), 1 = errors found.
It checks structure and ti2dac ingestion rules; it cannot check whether a claim is true
or whether a cited record supports it. That remains the author's and reviewer's job.
"""
import argparse
import json
import re
import sys
from pathlib import Path

REQUIRED = [
    '## 1. Executive summary',
    '## 2. Sample and analysis context',
    '## 3. How the malware works',
    '## 4. Attacker behaviours and techniques (MITRE ATT&CK)',
    '## 5. Defense evasion and anti-analysis',
    '## 6. Collection, theft and impact',
    '## 7. Configuration, command and control',
    '## 8. Host artifacts and forensic footprint',
    '## 9. Mitigations and hardening',
    '## 10. Hunting and response guidance',
    '## 11. Assessment, confidence and open questions',
    '## Indicators of compromise',
    '## Appendix B: YARA rules',
    '## Appendix D: Technical deep dive',
    '## Appendix E: Reproduction',
]
# Mirrors ti2dac pipeline._INCIDENT_HINTS: 3+ distinct hits switch ti2dac to incident mode.
INCIDENT = re.compile(
    r"incident report|incident summary|root cause|containment|eradication|lessons learned|post[- ]incident|"
    r"affected (host|system|user)s?|host was isolated|\bisolated\b|\bIR-\d|incident (id|number|ticket)|severity:|"
    r"timeline \(utc\)|first observed|patient zero|initial access vector", re.I)
# Mirrors ti2dac condense._KEEP_SECTION: these words keep a heading that would otherwise be dropped.
KEEP_WORDS = re.compile(r"\b(att&ck|mitre|ttps?|techniques?|timeline|summary|analysis|execution|persistence"
                        r"|discovery|lateral|credential|exfil|impact|evasion|command and control)\b", re.I)
EVENT_LINE = re.compile(r"^[^\S\n]*\{.*\}[^\S\n]*,?[^\S\n]*$")
PROFILE = re.compile(r"(?i)(?:[a-z]:\\{1,2}Users\\{1,2}(?!public\b|default\b)[^\\\s%]+|/home/[^/\s]+)")
EID = re.compile(r'\bE\d{7}\b')
HEADING = re.compile(r'^(#{1,6})\s+(.+?)\s*$')


def sections(lines):
    """Yield (level-2 heading or '', list of (lineno, line)) in order."""
    current, body = '', []
    for no, line in enumerate(lines, 1):
        if line.startswith('## ') and not line.startswith('### '):
            yield current, body
            current, body = line.strip(), []
        else:
            body.append((no, line))
    yield current, body


TACTIC_LINE = re.compile(r'^\*\*Tactic:\*\* .+?\. \*\*Status:\*\* .+?\. \*\*Confidence:\*\* (High|Medium|Low)\.\s*$')


def layout_warnings(lines):
    """Patterns scripts/render_report_pdf.py turns into the PDF layout (guide section 6). Warnings only."""
    out = []
    body = {head: [l for _, l in b] for head, b in sections(lines)}
    summary = body.get('## 1. Executive summary', [])
    if summary:
        if not any(re.match(r'^\|\s*At a glance\s*\|', l) for l in summary):
            out.append('Layout: section 1 has no "| At a glance | |" table (PDF cover subtitle and summary table)')
        if not any(l.startswith('**Bottom line:') for l in summary):
            out.append('Layout: section 1 has no "**Bottom line: ...**" line (PDF callout)')
        for key in ('Block', 'Hunt', 'Reset'):
            if not any(l.startswith(f'- **{key}:**') for l in summary):
                out.append(f'Layout: priority action "- **{key}:** ..." missing in section 1 (PDF action cards)')
    how = body.get('## 3. How the malware works', [])
    sub = None
    for l in how:
        if l.startswith('### '):
            sub = l[4:].strip()
        elif sub == 'Execution flow' and re.match(r'^\d+\. ', l) and not re.match(r'^\d+\. T\+\d', l):
            out.append(f'Layout: execution-flow item should start "T+mm:ss, ...": {l[:60]}')
    if how and not any(l.strip() == '### Attack flow' for l in how):
        out.append('Layout: section 3 has no "### Attack flow" text block (PDF flow diagram)')
    current, seen_tactic, seen_tel = None, False, False

    def close():
        if current and not seen_tactic:
            out.append(f'Layout: {current} lacks "**Tactic:** X. **Status:** Y. **Confidence:** Z." (PDF chips)')
        if current and not seen_tel:
            out.append(f'Layout: {current} lacks one "**Telemetry:** ... **Detection opportunity:** ..." paragraph')
    for l in body.get('## 4. Attacker behaviours and techniques (MITRE ATT&CK)', []):
        if l.startswith('### '):
            close()
            current, seen_tactic, seen_tel = l[4:].split('.')[0], False, False
        elif TACTIC_LINE.match(l):
            seen_tactic = True
        elif l.startswith('**Telemetry:**') and '**Detection opportunity:**' in l:
            seen_tel = True
    close()
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('report')
    ap.add_argument('--evidence', help='evidence.json of the run the report is based on')
    args = ap.parse_args()
    text = Path(args.report).read_text(encoding='utf-8')
    lines = text.splitlines()
    errors, warnings = [], []

    # Title and TLP
    if not lines or not re.match(r'^# .+: threat intelligence report\s*$', lines[0]):
        errors.append('Line 1 must be "# <Family> <type> <sha256[:12]>: threat intelligence report"')
    tlps = set(re.findall(r'\bTLP:\s*([A-Z+]+)', text))
    if not re.search(r'^TLP:(CLEAR|GREEN|AMBER|AMBER\+STRICT|RED)\s*$', text, re.M):
        errors.append('Missing a "TLP:<LEVEL>" line under the title')
    if len(tlps) > 1:
        errors.append(f'More than one TLP level mentioned: {sorted(tlps)}')

    # Required headings, in order
    found = [l.strip() for l in lines if l.startswith('## ')]
    pos = -1
    for h in REQUIRED:
        if h not in found:
            errors.append(f'Missing heading: {h}')
            continue
        idx = found.index(h)
        if idx < pos:
            errors.append(f'Heading out of order: {h}')
        pos = max(pos, idx)

    # Incident-mode wording
    hits = sorted({m.group(0).lower() for m in INCIDENT.finditer(text)})
    if hits:
        (errors if len(hits) >= 3 else warnings).append(f'Incident-report wording (ti2dac flips at 3): {hits}')

    main_words = 0
    for head, body in sections(lines):
        in_main = bool(re.match(r'## (\d+)\. ', head))
        in_appendix = head.startswith('## Appendix')
        replay = head.startswith('## Appendix C')
        fence = None
        for no, line in body:
            if line.lstrip().startswith('```'):
                lang = line.strip()[3:].strip().lower()
                fence = None if fence is not None else lang
                if fence == 'yara' and not head.startswith('## Appendix B'):
                    errors.append(f'line {no}: yara fence outside Appendix B (the rule validator scans every fence)')
                continue
            if in_main and fence is None:
                main_words += len(line.split())
            if not replay and EVENT_LINE.match(line):
                errors.append(f'line {no}: single-line JSON object (ti2dac replays it as a log event)')
            if PROFILE.search(line):
                errors.append(f'line {no}: user-profile path; use %USERPROFILE%/%APPDATA%/... or a repo-relative path')
            m = HEADING.match(line)
            if not m or fence is not None:
                continue
            title = m.group(2)
            if head.startswith('## 4.') and m.group(1) == '###':
                if not re.match(r'B\d+\. .+\(T1\d{3}(\.\d{3})?\)$', title):
                    errors.append(f'line {no}: behaviour heading must be "### B<n>. <Name> (T<id>)": {title}')
                if re.search(r'indicator|\bioc|hash|yara|appendix', title, re.I):
                    errors.append(f'line {no}: behaviour heading contains a word ti2dac drops: {title}')
            if head.startswith(('## Indicators', '## Appendix B')):
                errors.append(f'line {no}: no sub-headings allowed inside {head}')
            if in_appendix and not replay:
                if not re.match(r'Appendix [D-Z]\b', title):
                    errors.append(f'line {no}: appendix sub-heading must start with "Appendix <letter>": {title}')
                if KEEP_WORDS.search(title):
                    errors.append(f'line {no}: appendix sub-heading uses a ti2dac keep-word, so it would not be '
                                  f'dropped: {title}')

    warnings.extend(layout_warnings(lines))

    if main_words > 4500:
        warnings.append(f'Sections 1-11 have ~{main_words} words; ti2dac condenses to ~6K tokens. Move depth to Appendix D.')

    # Evidence IDs
    used = set(EID.findall(text))
    if not used:
        errors.append('No [E0000000] evidence IDs cited')
    if args.evidence:
        data = json.loads(Path(args.evidence).read_text(encoding='utf-8'))
        known = {r['id'] for r in data.get('records', [])}
        unknown = sorted(used - known)
        if unknown:
            errors.append(f'Evidence IDs not in {args.evidence}: {unknown[:20]}{" ..." if len(unknown) > 20 else ""}')
    else:
        warnings.append('No --evidence given: evidence IDs were not checked for existence')
    analyst = set(re.findall(r'\[(A\d+)\]', text))
    appendix_e = text.split('## Appendix E: Reproduction', 1)[1] if '## Appendix E: Reproduction' in text else ''
    undefined = sorted(a for a in analyst if not re.search(rf'\b{a}\b', appendix_e))
    if undefined:
        errors.append(f'Analyst finding IDs cited but not defined in Appendix E: {undefined}')

    for e in errors:
        print(f'ERROR   {e}')
    for w in warnings:
        print(f'WARNING {w}')
    print(f'{len(errors)} error(s), {len(warnings)} warning(s); {len(used)} evidence IDs, '
          f'{len(analyst)} analyst IDs, ~{main_words} words in sections 1-11')
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
