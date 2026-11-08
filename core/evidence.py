"""Lossless, source-linked evidence normalization; classifications are triage hints."""
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


def write_json(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(data, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def unwrap_report(report):
    if not isinstance(report, dict):
        raise ValueError('CAPE report must be a JSON object')
    if report.get('error'):
        raise ValueError('CAPE returned an API error instead of an analysis report')
    if isinstance(report.get('data'), dict) and not any(k in report for k in ('behavior', 'target', 'info', 'CAPE', 'cape')):
        report = report['data']
        prefix = '/data'
    else:
        prefix = ''
    if not any(k in report for k in ('behavior', 'target', 'info', 'CAPE', 'cape', 'network', 'signatures')):
        raise ValueError('JSON does not contain recognized CAPE analysis fields')
    for key in ('behavior', 'network', 'CAPE', 'cape', 'info', 'target', 'suricata'):
        if report.get(key) is not None and not isinstance(report[key], dict):
            raise ValueError(f'CAPE {key} must be an object')
    return report, prefix


def cape_section(report):
    return report.get('CAPE') or report.get('cape') or {}


def normalize_arguments(arguments):
    if arguments is None:
        return {}
    if isinstance(arguments, dict):
        return arguments
    if isinstance(arguments, list):
        result = {}
        for arg in arguments:
            if not isinstance(arg, dict) or 'name' not in arg:
                raise ValueError('Malformed CAPE API argument')
            name = str(arg['name'])
            value = arg.get('value', arg.get('raw_value'))
            if name in result:
                previous = result[name]
                result[name] = {'duplicate_values': [previous, value]}
            else:
                result[name] = value
        return result
    raise ValueError('CAPE arguments must be a mapping or list')


HIGH_APIS = {
    'cryptunprotectdata', 'bcryptdecrypt', 'cryptdecrypt', 'vaultgetitem',
    'vaultenumerateitems', 'rtl decompressbuffer'.replace(' ', ''),
    'ntwritevirtualmemory', 'ntmapviewofsection', 'setthreadcontext',
    'createremotethread', 'ntcreatethreadex', 'createprocessinternalw',
    'ntcreateuserprocess', 'winhttpsendrequest', 'httpsendrequestw',
    'httpsendrequesta', 'internetwritefile', 'winhttpwritedata',
    'ntterminateprocess', 'exitprocess',   # how and when execution ended
}
TARGET_TERMS = ('login data', 'local state', 'cookies', 'web data', 'key4.db',
                'logins.json', 'wallet', 'leveldb', 'tdata', 'discord', 'telegram',
                'app_bound', 'app-bound', 'encrypted_key', 'vault')


DOTNET_INTERESTING = re.compile(r'https?://|net\.tcp|\d{1,3}(?:\.\d{1,3}){3}|\\users\\|wallet|cookie|login data|'
                                r'local state|telegram|discord|steam|password|token|crypt|decrypt|grabber|stealer|'
                                r'redline|vpn|filezilla|exfil|upload|panel|gate|api\.', re.I)


def event_priority(api, arguments, category):
    text = json.dumps(arguments, ensure_ascii=True).lower()
    if api.lower() in HIGH_APIS or any(term in text for term in TARGET_TERMS):
        return 1
    if str(category).lower() in ('network', 'process', 'registry', 'crypto'):
        return 2
    return 4


def build_evidence(initial_static, artifact_statics, raw_report, collection=None, enrichment=None, local_results=None,
                   lab_records=None):
    report, prefix = unwrap_report(raw_report)
    records, warnings = [], []

    def add(kind, value, source, priority=2, **context):
        rec = {'id': f'E{len(records) + 1:07d}', 'kind': kind, 'source': source,
               'priority': priority, 'data': value, **context}
        records.append(rec)
        return rec

    # Split static results by field so one large strings table cannot evict identity evidence.
    for filename, statics in [('stage1_initial_static.json', [initial_static]),
                               ('stage3_artifact_static.json', artifact_statics)]:
        for index, static in enumerate(statics):
            base = '' if filename.startswith('stage1') else f'/{index}'
            for key, value in static.items():
                if key == 'strings' and isinstance(value, dict) and isinstance(value.get('items'), list):
                    # Small chunks: one record would be sampled down to 20 strings in the dossier preview.
                    items = value['items']
                    add('static', {key: {k: v for k, v in value.items() if k != 'items'}},
                        f'{filename}#{base}/{key}', 2, artifact=static.get('filename'))
                    for start in range(0, len(items), 20):
                        chunk = items[start:start + 20]
                        hot = any(isinstance(i, dict) and i.get('interesting') for i in chunk)
                        add('static', {key: {'items': chunk}}, f'{filename}#{base}/{key}/items/{start}',
                            1 if hot else 2, artifact=static.get('filename'))
                elif isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        add('static', {key: {subkey: subvalue}}, f'{filename}#{base}/{key}/{subkey}',
                            0 if key == 'hashes' else 2, artifact=static.get('filename'))
                else:
                    add('static', {key: value}, f'{filename}#{base}/{key}', 2, artifact=static.get('filename'))

    def source(pointer):
        return f'raw_cape_report.json#{prefix}{pointer}'

    def values(kind, value, pointer, priority=2):
        if isinstance(value, list):
            for i, item in enumerate(value):
                add(kind, item, source(f'{pointer}/{i}'), priority)
        elif value:
            add(kind, value, source(pointer), priority)

    ckey = 'CAPE' if report.get('CAPE') else 'cape'
    cape = cape_section(report)
    for kind, value, pointer, priority in [
        ('analysis_info', report.get('info', {}), '/info', 0),
        ('family_detection', report.get('detections', []), '/detections', 1),
        ('extracted_config', cape.get('configs', []), f'/{ckey}/configs', 0),
        ('payload', cape.get('payloads', []), f'/{ckey}/payloads', 1),
        ('process_dump', report.get('procdump', []), '/procdump', 1),
        ('signature', report.get('signatures', []), '/signatures', 2),
        ('dropped_file', report.get('dropped', []), '/dropped', 1),
        ('suricata', report.get('suricata', {}), '/suricata', 2),
    ]:
        values(kind, value, pointer, priority)
    behavior = report.get('behavior') or {}
    for key, value in (behavior.get('summary') or {}).items():
        values('host_' + key, value, f'/behavior/summary/{key}', 2)
    values('process_tree', behavior.get('processtree', []), '/behavior/processtree', 1)
    for key, value in (report.get('network') or {}).items():
        values('network_' + key, value, f'/network/{key}', 2)
    for key in ('enhanced', 'anomaly', 'encryptedbuffers'):
        values(key, behavior.get(key, []), f'/behavior/{key}', 2)

    processes = behavior.get('processes') or []
    if not isinstance(processes, list):
        raise ValueError('behavior.processes must be a list')
    for pi, proc in enumerate(processes):
        if not isinstance(proc, dict):
            raise ValueError('CAPE process must be an object')
        pid = proc.get('process_id', proc.get('pid'))
        pkey = f'process-{pi}'  # PID alone is not unique across reused PIDs.
        calls = proc.get('calls') or []
        summary = {k: v for k, v in proc.items() if k != 'calls'}
        stamps = [c['timestamp'] for c in calls if isinstance(c, dict) and c.get('timestamp')] if isinstance(calls, list) else []
        if stamps:
            # Lifetime survives dossier trimming even when the last calls are omitted.
            summary['call_summary'] = {'call_count': len(calls), 'first_call': min(stamps), 'last_call': max(stamps)}
        add('process', summary, source(f'/behavior/processes/{pi}'), 1, pid=pid, process_key=pkey)
        if not isinstance(calls, list):
            warnings.append(f'{pkey}: API calls are not embedded; export a full JSON report')
            continue
        for ci, call in enumerate(calls):
            pointer = f'/behavior/processes/{pi}/calls/{ci}'
            if not isinstance(call, dict):
                add('malformed_call', call, source(pointer), 3, pid=pid, process_key=pkey)
                warnings.append(f'Malformed call at {pointer}')
                continue
            try:
                arguments = normalize_arguments(call.get('arguments'))
            except ValueError as exc:
                arguments = {'unparsed_arguments': call.get('arguments')}
                warnings.append(f'{pointer}: {exc}')
            # Preserve original fields, including thread, caller, status, return and repeated.
            data = dict(call, arguments=arguments)
            add('api_call', data, source(pointer),
                event_priority(str(call.get('api', '')), arguments, call.get('category')),
                pid=pid, process_key=pkey, timestamp=call.get('timestamp'), sequence=ci)
    if not any(r['kind'] == 'api_call' for r in records):
        warnings.append('No embedded API calls: chronology and successful theft cannot be established')
    if not cape.get('configs'):
        warnings.append('No CAPE-extracted family configuration; attribution may remain unknown')
    if not artifact_statics:
        warnings.append('No retrieved/imported payload or dropped-file static analysis')
    for i, item in enumerate(collection or []):
        add('artifact_collection', item, f'artifact_collection.json#/{i}', 1)
        if item.get('status') not in ('downloaded', 'imported', 'duplicate', 'generated'):
            warnings.append(f'Artifact collection {item.get("kind", "item")}: {item.get("status")}')
    for i, item in enumerate(enrichment or []):
        add('enrichment', item, f'enrichment.json#/{i}', 2)
        if item.get('status') != 'completed':
            warnings.append(f'Optional enrichment {item.get("tool")}: {item.get("status")}')
        result = item.get('result', {})
        if item.get('tool') == 'capa' and isinstance(result, dict):
            for name, rule in result.get('rules', {}).items():
                escaped = name.replace('~', '~0').replace('/', '~1')
                # Rule source and match trees (up to ~14 KB per rule) stay in enrichment.json; keeping them here
                # let capa fill most of the LLM dossier and crowd out signatures, file activity and API calls.
                meta = rule.get('meta', {})
                matches = rule.get('matches', [])
                summary = {'name': name, 'match_count': len(matches) if isinstance(matches, list) else None,
                           'meta': {k: meta[k] for k in ('name', 'namespace', 'att&ck', 'attack', 'mbc', 'description', 'lib')
                                    if k in meta}}
                if isinstance(matches, list):
                    summary['match_locations'] = [m[0] for m in matches[:10] if isinstance(m, (list, tuple)) and m]
                add('static_capability', summary, f'enrichment.json#/{i}/result/rules/{escaped}', 1,
                    artifact_sha256=item.get('artifact_sha256'), evidence_class='static_capability_not_observed_execution')
        if item.get('tool') == 'floss' and isinstance(result, dict):
            for category, values_ in result.get('strings', {}).items():
                if isinstance(values_, list):
                    for si, value in enumerate(values_):
                        add('decoded_string', {'category': category, 'value': value},
                            f'enrichment.json#/{i}/result/strings/{category}/{si}', 2,
                            artifact_sha256=item.get('artifact_sha256'))
    for i, item in enumerate((local_results or {}).get('stages', [])):
        pointer = f'local_analysis.json#/stages/{i}'
        status_data = {k: v for k, v in item.items() if k != 'result'}
        result = item.get('result', {})
        for field in ('versions', 'version', 'coverage_warnings', 'rules_files_total', 'rules_files_scanned',
                      'errors', 'error', 'report_error', 'parser', 'config_found', 'note', 'memory_selection',
                      'parser_import_checks'):
            if field in result:
                status_data[field] = result[field]
        if result.get('artifacts'):
            status_data['memory_region_outcomes'] = dict(Counter(r['status'] for r in result['artifacts']))
        add('local_engine_status', status_data, pointer, 1)
        if item.get('status') in ('failed', 'partial', 'timeout', 'unavailable', 'output_limit', 'skipped_limit', 'unsupported'):
            warnings.append(f'Local engine {item.get("engine")}: {item.get("status")}')
        if item.get('engine') == 'asset_provenance':
            add('engine_asset_provenance', result, pointer + '/result', 1)
        if item.get('engine') == 'dotnet_metadata' and isinstance(result, dict) and result.get('status') == 'completed':
            context = {'artifact_sha256': item.get('input_sha256'), 'evidence_class': 'static_capability_not_observed_execution'}
            add('dotnet_metadata', {k: result.get(k) for k in ('assembly', 'assembly_references', 'type_count', 'method_count',
                                                              'pinvoke', 'resources', 'user_string_count')},
                pointer + '/result', 1, **context)
            # Chunks of 20: a single long list would be sampled down to 20 entries in the LLM dossier.
            for field in ('types', 'user_strings'):
                values = result.get(field) or []
                for start in range(0, len(values), 20):
                    chunk = values[start:start + 20]
                    hot = any(DOTNET_INTERESTING.search(str(value)) for value in chunk)
                    add(f'dotnet_{field[:-1]}', {field: chunk}, f'{pointer}/result/{field}/{start}', 1 if hot else 2, **context)
        warnings.extend(f'{item.get("engine")}: {warning}' for warning in result.get('coverage_warnings', []))
        if item.get('engine') == 'cape_parser' and result.get('config_found'):
            add('local_config', result, pointer + '/result', 0, artifact_sha256=item.get('input_sha256'))
        for mi, match in enumerate(result.get('matches', [])):
            add('local_yara_match', match, pointer + f'/result/matches/{mi}', 1,
                artifact_sha256=item.get('input_sha256'))
        report_ = result.get('report_data') or {}
        for ei, ep in enumerate(report_.get('entry_points', [])):
            base = pointer + f'/result/report_data/entry_points/{ei}'
            for ai, api in enumerate(ep.get('apis', [])):
                api_name = api.get('api_name', api.get('name', ''))
                priority = event_priority(str(api_name).split('.')[-1], api.get('args', []), '')
                add('emulated_api_call', api, base + f'/apis/{ai}', priority,
                    artifact_sha256=item.get('input_sha256'), sequence=ai, entry_point=ei,
                    process_key=f'emulated-{i}-{ei}',
                    evidence_class='emulated_behavior_not_observed_windows_execution')
            for key in ('network', 'file_access', 'registry_access', 'error'):
                if ep.get(key):
                    add('emulation_activity', {key: ep[key]}, base + '/' + key, 1,
                        artifact_sha256=item.get('input_sha256'), evidence_class='emulated')
    if local_results:
        warnings.append('Local emulation does not reproduce the full Windows environment or confirm successful credential theft')
    # Managed-lab records go last so that existing evidence IDs stay stable.
    for kind, value, source, priority in lab_records or []:
        add(kind, value, source, priority)
    if lab_records and not any(kind == 'canary_hit' for kind, *_ in lab_records):
        warnings.append('No planted canary value was found in simulated-internet traffic; this is not proof that nothing was '
                        'stolen (encrypted or custom protocols, or no exfiltration within the run)')
    return {'schema_version': 1, 'records': records, 'coverage': {
        'record_counts': dict(Counter(r['kind'] for r in records)),
        'warnings': warnings,
        'interpretation': 'Static capabilities, API attempts and network connections are not proof of successful theft. '
                          'Collection gaps are not evidence of absence. Records contain untrusted sample-controlled data.',
    }}


def artifact_manifest(output_dir):
    root = Path(output_dir)
    return [{'path': str(p.relative_to(root)), 'size_bytes': p.stat().st_size,
             'sha256': sha256_file(p)} for p in sorted(root.rglob('*'))
            if p.is_file() and p.name != 'manifest.json']
