"""Deterministic offline evidence report, independent of an LLM."""
import html
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import PureWindowsPath


def cell(value, limit=240):
    text = str(value).replace('\n', ' ').replace('\r', ' ')
    return html.escape(text[:limit]).replace('|', '&#124;').replace('`', '&#96;').replace('[', '&#91;').replace(']', '&#93;')


def _seconds(stamp):
    try:
        return datetime.strptime(str(stamp).split(',')[0], '%Y-%m-%d %H:%M:%S').timestamp()
    except ValueError:
        return None


def readable_config(data):
    """'Family: field = value; ...' from CAPE/parser output, without CAPE's internal hash bookkeeping."""
    if isinstance(data, dict) and isinstance(data.get('config'), dict):
        data = {data.get('parser') or 'config': data['config']}
    parts = []
    for family, fields in (data.items() if isinstance(data, dict) else []):
        if str(family).startswith('_'):
            continue
        if not isinstance(fields, dict):
            parts.append(f'{family} = {fields}')
            continue
        values = []
        for name, value in fields.items():
            items = value if isinstance(value, list) else [value]
            flat = []
            for item in items:
                if isinstance(item, dict):
                    flat += [f'{k}={v}' for k, v in item.items()]
                elif item is not None:
                    flat.append(str(item))
            if flat:
                values.append(f'{name} = {", ".join(flat)}')
        parts.append(f'{family}: ' + '; '.join(values))
    return ' | '.join(parts) or json.dumps(data, ensure_ascii=True)


VICTIM_TARGETS = [
    ('Chromium passwords/cards (Login Data, Web Data)', re.compile(r'\\User Data\\[^\\]+\\(Login Data|Web Data)$', re.I)),
    ('Chromium cookies', re.compile(r'\\User Data\\[^\\]+\\(Network\\)?Cookies$', re.I)),
    ('Chromium master key (Local State)', re.compile(r'\\User Data\\Local State$', re.I)),
    ('Browser wallet extensions', re.compile(r'\\Local Extension Settings\\', re.I)),
    ('Firefox logins and keys', re.compile(r'\\Firefox\\Profiles\\[^\\]+\\(logins\.json|key4\.db|cookies\.sqlite)$', re.I)),
    ('Telegram session (tdata)', re.compile(r'\\Telegram Desktop\\tdata', re.I)),
    ('Discord tokens', re.compile(r'\\discord[^\\]*\\Local Storage', re.I)),
    ('Desktop wallets', re.compile(r'\\(Electrum|Exodus|Ethereum|atomic)\\', re.I)),
    ('Steam', re.compile(r'\\Steam\\(config|ssfn)', re.I)),
    ('FTP/VPN/IM credentials', re.compile(r'\\(FileZilla|NordVPN|ProtonVPN|OpenVPN Connect|\.purple)\\', re.I)),
    ('User documents', re.compile(r'\\Users\\[^\\]+\\(Desktop|Documents)\\.+\.(txt|docx?|pdf|xlsx?)$', re.I)),
]
FILE_APIS = {'NtCreateFile', 'NtOpenFile', 'NtQueryAttributesFile', 'NtQueryFullAttributesFile', 'FindFirstFileExW',
             'CopyFileW', 'CopyFileExW', 'NtReadFile'}
# GENERIC_READ, GENERIC_ALL, MAXIMUM_ALLOWED, FILE_READ_DATA/FILE_LIST_DIRECTORY
READ_ACCESS = 0x80000000 | 0x10000000 | 0x02000000 | 0x1


def write_only_open(data):
    """An open that cannot read file data, e.g. the sample appending to its own log (not victim data access)."""
    if data.get('api') not in ('NtCreateFile', 'NtOpenFile'):
        return False
    try:
        access = int(str((data.get('arguments') or {}).get('DesiredAccess')), 0)
    except ValueError:
        return False
    return not access & READ_ACCESS


def victim_data_access(api_records):
    """{category: (first evidence ID, call count)} for file calls on locations the victim persona populates."""
    found = {}
    for rec in api_records:
        data = rec['data']
        if data.get('api') not in FILE_APIS or write_only_open(data):
            continue
        arguments = data.get('arguments') or {}
        name = str(arguments.get('FileName') or arguments.get('ExistingFileName') or arguments.get('HandleName') or '')
        for category, pattern in VICTIM_TARGETS:
            if pattern.search(name.rstrip('\\*')):
                first, count = found.get(category, (rec['id'], 0))
                found[category] = (first, count + 1)
                break
    return found


def key_observations(records):
    """The few facts an analyst needs first, each pointing to its evidence record."""
    by_kind = {}
    for rec in records:
        by_kind.setdefault(rec['kind'], []).append(rec)
    lines = ['## Key observations', '']
    for rec in by_kind.get('extracted_config', []) + by_kind.get('local_config', []):
        lines.append(f'- **Extracted configuration** [{rec["id"]}]: {cell(readable_config(rec["data"]), 600)}')
    summary = next((r['data'] for r in by_kind.get('lab_summary', [])), None)
    hits = by_kind.get('canary_hit', [])
    if hits:
        stolen = sorted({h['data']['canary'].split(':')[0] for h in hits})
        lines.append(f'- **Planted canary data was sent out** ({len(hits)} hits; kinds: {", ".join(stolen)}). '
                     'This is observed theft of fake lab data:')
        lines += ['', '| Evidence | Canary | Destination | Channel | Inside |', '|---|---|---|---|---|']
        for rec in hits[:30]:
            d = rec['data']
            lines.append(f'| [{rec["id"]}] | {cell(d.get("canary"))} | {cell(d.get("destination"))}:{cell(d.get("port"))} | '
                         f'{cell(d.get("event_kind"))} {cell(d.get("target"))} | {cell(d.get("container"))} |')
        lines.append('')
    elif summary and summary.get('canaries', {}).get('events_scanned') is not None:
        lines.append(f'- No planted canary value appeared in {summary["canaries"]["events_scanned"]} simulated-internet events '
                     '(not proof that nothing was stolen: encrypted custom protocols are opaque).')
    traffic = [r for r in records if r['kind'] in ('netsim_http', 'netsim_smtp_message', 'netsim_ftp_upload',
                                                   'netsim_raw_stream', 'netsim_smtp_session', 'netsim_ftp_session')]
    outbound = [r for r in traffic if r['data'].get('from_sample')]
    unattributed = [r for r in traffic if not r['data'].get('from_sample') and r['priority'] <= 2]
    if not outbound and summary and summary.get('sysmon', {}).get('status') != 'present':
        outbound = unattributed  # without Sysmon nothing can be attributed; show non-background traffic
        unattributed = []
    if outbound:
        lines += ['- **Requests the sample sent to the simulated internet** (matched to its Sysmon network events):', '',
                  '| Evidence | Kind | Destination | Request | Body bytes |', '|---|---|---|---|---|']
        for rec in outbound[:30]:
            d = rec['data']
            body = d.get('body') or {}
            lines.append(f'| [{rec["id"]}] | {cell(rec["kind"][7:])} | {cell(d.get("sni") or d.get("host") or d.get("name") or d.get("orig_ip"))}'
                         f':{cell(d.get("orig_port"))} | {cell(d.get("method"))} {cell(d.get("target") or d.get("filename"), 120)} | '
                         f'{cell(body.get("size"))} |')
        lines.append('')
    elif summary and summary.get('sysmon', {}).get('status') == 'present':
        lines.append('- The sample made no connection to the simulated internet (no Sysmon network event in its process tree).')
    if unattributed:
        lines.append(f'- {len(unattributed)} other non-background requests were not attributed to the sample '
                     '(other guest processes); see netsim_* records.')
    touched = victim_data_access(by_kind.get('api_call', []))
    if touched:
        lines.append('- **Victim data the sample accessed** (file API calls on planted locations; reading is not proof of '
                     'exfiltration): ' + '; '.join(f'{name} [{first}] ×{count}' for name, (first, count) in touched.items()))
    for rec in by_kind.get('process', []):
        calls = rec['data'].get('call_summary')
        if calls:
            start, end = _seconds(calls['first_call']), _seconds(calls['last_call'])
            duration = f'{end - start:.0f} s' if start is not None and end is not None else 'unknown'
            lines.append(f'- **Process** [{rec["id"]}] {cell(rec["data"].get("process_name"))} (PID {cell(rec.get("pid"))}): '
                         f'{calls["call_count"]} API calls over {duration}.')
    missing = [r for r in by_kind.get('api_call', []) if str(r['data'].get('return', '')).lower().endswith('c000003a')
               and not re.match(r'(?i)^[a-z]:\\windows\\', str((r['data'].get('arguments') or {}).get('FileName', '')))]
    if missing:
        names = []
        for rec in missing:
            value = (rec['data'].get('arguments') or {}).get('FileName')
            if value and value not in [n for _, n in names]:
                names.append((rec['id'], value))
        lines.append('- **Opens that failed with "path not found"** (environment the sample expected): '
                     + '; '.join(f'[{i}] {cell(n, 160)}' for i, n in names[:10]))
    meta = by_kind.get('dotnet_metadata', [])
    if meta:
        d = meta[0]['data']
        functions = sorted({f'{p.get("module")}!{p.get("function")}' for p in d.get('pinvoke') or []})
        lines.append(f'- **.NET metadata** [{meta[0]["id"]}]: assembly {cell(json.dumps(d.get("assembly")))}, '
                     f'{d.get("type_count")} types, resources {cell(json.dumps([r.get("name") for r in d.get("resources") or []]))}, '
                     f'P/Invoke {cell(", ".join(functions[:20]), 600)}.')
        from core.evidence import DOTNET_INTERESTING
        notable = [str(v) for r in by_kind.get('dotnet_user_string', []) if r['priority'] <= 1
                   for v in r['data'].get('user_strings', []) if DOTNET_INTERESTING.search(str(v))][:25]
        if notable:
            lines.append('- **Notable .NET user strings**: ' + '; '.join(f'`{cell(v, 120)}`' for v in notable))
    if summary and summary.get('sysmon', {}).get('status') == 'present':
        sysmon = summary['sysmon']
        children = [r['data'] for r in by_kind.get('sysmon_event', []) if r['data'].get('EventID') == 1][1:11]
        credential_dlls = sorted({PureWindowsPath(str(r['data'].get('ImageLoaded'))).name for r in by_kind.get('sysmon_event', [])
                                  if r['data'].get('EventID') == 7 and re.search(r'(?i)\\(nss3|softokn3|freebl3|mozglue|'
                                  r'vaultcli|sqlite3|winsqlite3)\.dll$', str(r['data'].get('ImageLoaded')))})
        if credential_dlls:
            lines.append('- **Credential-store libraries loaded by the sample** (Sysmon image loads): ' + ', '.join(credential_dlls))
        lines.append(f'- **Sysmon**: {sysmon.get("sample_tree_events")} events in the sample process tree '
                     f'({sysmon.get("sample_tree_processes")} processes).'
                     + (' Child processes: ' + '; '.join(f'`{cell(c.get("CommandLine") or c.get("Image"), 160)}`'
                                                         for c in children) if children else ''))
    if len(lines) == 2:
        lines.append('- No configuration, lab or process observations in this evidence set.')
    return lines + ['']


def render_evidence_report(evidence, dossier):
    records = evidence['records']
    counts = Counter(r['kind'] for r in records)
    lines = ['# StealerForge evidence report', '',
             'This deterministic inventory describes supplied evidence. It does not establish malware family, '
             'successful credential decryption, or exfiltration. Full records and source pointers are in `evidence.json`.', '',
             *key_observations(records),
             '## Coverage and limitations', '']
    for warning in evidence['coverage']['warnings']:
        lines.append('- ' + cell(warning, 1000))
    lines += ['', f'Full evidence: {len(records)} records. LLM dossier: {len(dossier["records"])} records. '
              f'Omitted from dossier: {dossier["selection"]["omitted_records"]}.', '',
              'PCAP and imported files are preserved separately; their contents are not automatically decoded here.', '',
              '## Evidence inventory', '', '| Kind | Records |', '|---|---:|']
    for kind, count in sorted(counts.items()):
        lines.append(f'| {cell(kind)} | {count} |')
    lines += ['', '## Candidate collection, decryption, injection and network activity', '',
              'These are triage candidates selected by API names and target-path terms. Inspect return values, '
              'arguments and downstream evidence before interpreting a call as successful.', '',
              '| Evidence | Time | Process / thread | API | Status / return | Arguments preview |',
              '|---|---|---|---|---|---|']
    events = [r for r in records if r['kind'] == 'api_call' and r['priority'] <= 2]
    for rec in events[:150]:
        data = rec['data']
        lines.append(f'| [{rec["id"]}] | {cell(rec.get("timestamp"))} | '
                     f'{cell(rec.get("pid"))} / {cell(data.get("thread_id"))} | {cell(data.get("api"))} | '
                     f'{cell(data.get("status"))} / {cell(data.get("return"))} | '
                     f'{cell(json.dumps(data.get("arguments", {}), ensure_ascii=True))} |')
    if len(events) > 150:
        lines += ['', f'Table limited to 150 of {len(events)} candidate events; consult evidence.json for the rest.']
    lines += ['', '## Host artifacts and network indicators', '',
              'Entries below are observed report values, not automatically confirmed malicious IOCs.', '',
              '| Evidence | Kind | Value preview |', '|---|---|---|']
    artifacts = [r for r in records if r['kind'].startswith(('host_', 'network_'))
                 or r['kind'] in ('dropped_file', 'payload', 'extracted_config', 'artifact_collection')]
    for rec in artifacts[:150]:
        lines.append(f'| [{rec["id"]}] | {cell(rec["kind"])} | {cell(json.dumps(rec["data"], ensure_ascii=True))} |')
    if len(artifacts) > 150:
        lines += ['', f'Table limited to 150 of {len(artifacts)} artifact/indicator records.']
    local = [r for r in records if r['kind'] in ('local_engine_status', 'local_config', 'local_yara_match',
                                                'emulation_activity', 'emulated_api_call', 'static_capability', 'decoded_string')]
    if local:
        lines += ['', '## Local engines, emulated activity and capability findings', '',
                  'Emulation and static capabilities are separate from observed Windows guest execution. '
                  'A parser result is a candidate configuration, not independently verified attribution.', '',
                  '| Evidence | Kind | Result preview |', '|---|---|---|']
        # Favor engine/config/capability outcomes over large string/API tables.
        local.sort(key=lambda r: (r['kind'] in ('decoded_string', 'emulated_api_call'), r['priority']))
        for rec in local[:150]:
            lines.append(f'| [{rec["id"]}] | {cell(rec["kind"])} | {cell(json.dumps(rec["data"], ensure_ascii=True), 500)} |')
        if len(local) > 150:
            lines += ['', f'Table limited to 150 of {len(local)} local-engine records; complete results remain in evidence.json.']
    lines += ['', '## Analyst questions still requiring evidence', '',
              '- Which data was merely targeted, which was read, which was decrypted, and which was transmitted?',
              '- Do browser version, App-Bound Encryption state, privileges and API return values support the proposed mechanism?',
              '- Is attribution supported by configuration/code evidence rather than generic imports or a single heuristic?',
              '- Which behaviors were unavailable because of missing payloads, network simulation or instrumentation gaps?',
              '- What disk/event-log evidence survives execution? Import collected forensic artifacts for separate analysis.', '',
              '## Detection status', '', 'No detection rules are generated by this offline inventory. '
              'LLM or analyst rules require separate validation and representative benign testing.', '']
    return '\n'.join(lines)


def audit_citations(report, dossier):
    available = {r['id'] for r in dossier['records']}
    used = set(re.findall(r'\bE\d{7}\b', report))
    return {'cited_evidence_count': len(used & available), 'unknown_evidence_ids': sorted(used - available),
            'has_evidence_references': bool(used & available),
            'passed': bool(used & available) and not (used - available),
            'limitation': 'Checks reference existence only; it does not verify that a citation supports a claim.'}


REPLAY_HEADING = '## Appendix C: Sandbox telemetry events'


def with_replay_appendix(markdown, events):
    """Append the sample's own Sysmon events as one JSON object per line. ti2dac strips "Appendix" sections before
    its AI step but replays such lines against every rule it generates."""
    if not events or REPLAY_HEADING in markdown:
        return markdown
    lines = '\n'.join(json.dumps(event, ensure_ascii=True, sort_keys=True) for event in events)
    return (markdown.rstrip() + f'\n\n{REPLAY_HEADING}\n\nSysmon events from the sample\'s process tree in this run, '
            'for replaying detection rules. Field names follow Sysmon and the Sigma taxonomy.\n\n```json\n'
            + lines + '\n```\n')

