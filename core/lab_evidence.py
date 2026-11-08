"""Managed-lab evidence beyond the CAPE report: simulated-internet events, canary hits and Sysmon telemetry.

Sysmon events are kept in Sysmon's own field names (Image, CommandLine, TargetFilename, ...), which are the
Sigma taxonomy names, so the same events can be replayed against generated Sigma rules (ti2dac).
"""
import json
from pathlib import Path
import re

MAX_EVENTS = 20000
MAX_SYSMON_BYTES = 256 * 1024 * 1024
MAX_REPLAY_EVENTS = 400
# Windows and browser background traffic seen in every run; still recorded, but ranked below sample traffic.
BACKGROUND = re.compile(r'(^|\.)(microsoft\.com|msftncsi\.com|msftconnecttest\.com|windowsupdate\.com|windows\.com|'
                        r'live\.com|bing\.com|msn\.com|office\.net|office\.com|onenote\.net|skype\.com|gvt1\.com|'
                        r'gstatic\.com|googleapis\.com|mozilla\.(com|net|org)|firefox\.com|digicert\.com|'
                        r'msedge\.net|azureedge\.net|akamaized\.net|edgesuite\.net|lencr\.org|host\.lan)$', re.I)
SYSMON_KEEP = {1, 3, 5, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 22, 23, 25, 26}


def _background(event):
    name = event.get('sni') or event.get('host') or event.get('name') or event.get('qname') or ''
    return bool(BACKGROUND.search(name.split(':')[0]))


def netsim_records(directory, sample_destinations=frozenset()):
    """Simulator events as evidence. sample_destinations holds (ip, port) pairs the sample's own processes
    connected to (Sysmon event 3); the simulator itself cannot tell which guest process sent a request."""
    events_file = Path(directory) / 'events.jsonl'
    if not events_file.is_file():
        return [], {'status': 'absent'}
    records, counts = [], {}
    with events_file.open(encoding='utf-8', errors='replace') as stream:
        for index, line in enumerate(stream):
            if index >= MAX_EVENTS:
                break
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = event.get('kind')
            counts[kind] = counts.get(kind, 0) + 1
            if kind in ('started',):
                continue
            if (event.get('orig_ip'), str(event.get('orig_port'))) in sample_destinations:
                event = dict(event, from_sample=True)
                priority = 0 if kind in ('http', 'smtp_message', 'ftp_upload', 'raw_stream') else 1
            elif _background(event):
                priority = 4
            elif kind in ('smtp_message', 'smtp_session', 'ftp_upload', 'ftp_session', 'raw_stream', 'http'):
                priority = 2
            else:
                priority = 3
            records.append((f'netsim_{kind}', event, f'netsim/events.jsonl#{event.get("seq")}', priority))
    return records, {'status': 'present', 'event_counts': counts}


def parse_sysmon(path):
    from defusedxml import ElementTree
    path = Path(path)
    if not path.is_file():
        return None
    if path.stat().st_size > MAX_SYSMON_BYTES:
        raise ValueError('Sysmon export exceeds the processing limit')
    root = ElementTree.fromstring(path.read_bytes())
    events = []
    for node in root.iter():
        if not node.tag.endswith('}Event') and node.tag != 'Event':
            continue
        event = _event(node)
        if event.get('EventID') in SYSMON_KEEP:
            events.append(event)
    events.sort(key=lambda e: (e.get('UtcTime') or e.get('TimeCreated') or '', e.get('EventID', 0)))
    return events


SYSMON_EVTX = re.compile(r'^(?:\d+_)?Microsoft-Windows-Sysmon%4Operational\.evtx$')


def _evtx_records(path, events):
    from defusedxml import ElementTree
    import Evtx.Evtx as evtx
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                node = ElementTree.fromstring(record.xml())
            except Exception:
                continue
            event = _event(node)
            if event.get('EventID') in SYSMON_KEEP:
                events[record.record_num()] = event


def _sorted(events):
    return sorted(events.values(), key=lambda e: (e.get('UtcTime') or e.get('TimeCreated') or '', e.get('EventID', 0)))


def parse_sysmon_evtx(path):
    """Sysmon events from one exported channel (sysmon.evtx), or from CAPE's evtx.zip, whose periodic
    snapshots are merged by record ID."""
    import tempfile
    import zipfile
    events = {}
    path = Path(path)
    if path.stat().st_size > MAX_SYSMON_BYTES:
        raise ValueError('Sysmon export exceeds the processing limit')
    if path.suffix == '.evtx':
        _evtx_records(path, events)
        return _sorted(events)
    with zipfile.ZipFile(path) as archive:
        members = [m for m in archive.infolist() if SYSMON_EVTX.match(m.filename) and m.file_size <= MAX_SYSMON_BYTES]
        for member in members:
            with tempfile.NamedTemporaryFile(suffix='.evtx') as temporary:
                with archive.open(member) as source:
                    temporary.write(source.read(MAX_SYSMON_BYTES))
                temporary.flush()
                _evtx_records(temporary.name, events)
    return _sorted(events)


def _event(node):
    event = {}
    for child in node.iter():
        tag = child.tag.rsplit('}', 1)[-1]
        if tag == 'EventID':
            event['EventID'] = int(child.text or 0)
        elif tag == 'TimeCreated':
            event['TimeCreated'] = child.get('SystemTime')
        elif tag == 'Data' and child.get('Name'):
            event[child.get('Name')] = child.text or ''
    return event


def sysmon_events(evidence_dir):
    """Sysmon events collected for a run: the whole-channel export (sysmon_export module), CAPE's sysmon.xml,
    or, for older runs, the Sysmon snapshots in evtx.zip (which can have gaps)."""
    evidence_dir = Path(evidence_dir)
    export = next(iter(sorted(evidence_dir.glob('cape/analyses/*/sysmon/sysmon.evtx'))), None)
    if export:
        return parse_sysmon_evtx(export)
    xml = next(iter(sorted(evidence_dir.glob('cape/analyses/*/sysmon/sysmon.xml'))), None)
    if xml:
        return parse_sysmon(xml)
    archive = next(iter(sorted(evidence_dir.glob('cape/analyses/*/evtx/evtx.zip'))), None)
    return parse_sysmon_evtx(archive) if archive else None


def sample_tree(events, cape_pids):
    """Process GUIDs of the sample and everything it started, anchored on CAPE's monitored PIDs."""
    pids = {str(pid) for pid in cape_pids}
    tree = {e['ProcessGuid'] for e in events if e.get('EventID') == 1 and e.get('ProcessId') in pids and e.get('ProcessGuid')}
    if not tree:
        tree = {e['ProcessGuid'] for e in events if e.get('ProcessId') in pids and e.get('ProcessGuid')}
    changed = True
    while changed:
        children = {e['ProcessGuid'] for e in events if e.get('EventID') == 1 and e.get('ParentProcessGuid') in tree}
        changed = not children <= tree
        tree |= children
    return tree


# CAPE's analyzer and result folders: C:\<random letters>\{CAPE,memory,data,...}. Its monitor runs inside the
# sample's process, so Sysmon attributes these writes to the sample.
HARNESS_PATH = re.compile(r'^[A-Za-z]:\\[A-Za-z0-9_-]{5,16}\\(CAPE|memory|data|logs|files|procdump|shots|debugger|'
                          r'dll|bin|lib|modules|aux|tlsdump|selfextracted|sysmon|evtx|curtain|analyzer\.py)(\\|$)', re.I)


def in_tree(event, tree, harness_pipes=()):
    if HARNESS_PATH.match(event.get('TargetFilename') or ''):
        return False
    if event.get('EventID') in (17, 18) and event.get('PipeName', '').lstrip('\\') in harness_pipes:
        return False
    # Key creation fires on every certificate-store or settings open; value writes (13) carry persistence.
    if event.get('EventID') == 12 and event.get('EventType') == 'CreateKey':
        return False
    return any(event.get(field) in tree for field in ('ProcessGuid', 'SourceProcessGuid'))


def harness_pipes(evidence_dir):
    """Names of the CAPE monitor's pipes, from the analyzer log."""
    names = set()
    for log in Path(evidence_dir).glob('cape/analyses/*/analysis.log'):
        with log.open(encoding='utf-8', errors='replace') as stream:
            for line in stream.readlines(1048576):
                match = re.search(r'Pipe server name: \\\\\.\\PIPE\\(\S+)', line)
                if match:
                    names.add(match.group(1))
    return names


def load(evidence_dir, raw_report):
    """Records for build_evidence plus Sigma-field events for rule replay."""
    evidence_dir = Path(evidence_dir)
    records, summary = [], {}
    processes = [p for p in (raw_report.get('behavior') or {}).get('processes') or [] if isinstance(p, dict)]
    # Anchor on the submitted sample only. CAPE also follows the sample's COM/WMI calls into svchost, dllhost and
    # WmiPrvSE; using those as roots would pull whole Windows service trees into the sample's telemetry.
    cape_pids = [processes[0].get('process_id', processes[0].get('pid'))] if processes else []
    events = sysmon_events(evidence_dir)
    related = []
    if events is not None:
        tree = sample_tree(events, cape_pids)
        related = [e for e in events if in_tree(e, tree, harness_pipes(evidence_dir))]
    destinations = frozenset((e.get('DestinationIp'), str(e.get('DestinationPort'))) for e in related if e.get('EventID') == 3)
    netsim, summary['netsim'] = netsim_records(evidence_dir / 'netsim', destinations)
    summary['netsim']['sample_destinations'] = sorted(f'{ip}:{port}' for ip, port in destinations)
    records.extend(netsim)
    hits_file = evidence_dir / 'canary_hits.json'
    if hits_file.is_file():
        hits = json.loads(hits_file.read_text())
        summary['canaries'] = {k: hits.get(k) for k in ('canaries', 'events_scanned', 'blobs_scanned', 'stolen_kinds', 'note')}
        for index, hit in enumerate(hits.get('hits', [])[:500]):
            records.append(('canary_hit', dict(hit, evidence_class='observed_exfiltration_of_planted_fake_data'),
                            f'canary_hits.json#/hits/{index}', 0))
    else:
        summary['canaries'] = {'note': 'No canary scan for this run'}
    replay = []
    if events is None:
        summary['sysmon'] = {'status': 'absent'}
    else:
        summary['sysmon'] = {'status': 'present', 'events': len(events), 'sample_tree_processes': len(tree),
                             'sample_tree_events': len(related)}
        for index, event in enumerate(related[:MAX_EVENTS]):
            priority = 1 if event['EventID'] in (1, 3, 8, 10, 22, 25) else 2
            records.append(('sysmon_event', event, f'sysmon.xml#sample-tree/{index}', priority))
        replay = related[:MAX_REPLAY_EVENTS]
    records.append(('lab_summary', summary, 'managed lab', 0))
    return records, replay, summary
