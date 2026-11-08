"""Bounded Windows EVTX/XML/JSONL normalization. No artifact execution."""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def event_xml(xml):
    from defusedxml import ElementTree as ET
    root = ET.fromstring(xml)
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    def node(name):
        return root.find('e:System/e:' + name, ns)
    def text(name):
        element = node(name)
        return element.text if element is not None else None
    fields = {}
    for i, element in enumerate(root.findall('e:EventData/e:Data', ns)):
        name = element.get('Name', str(i))
        value = element.text or ''
        if name in fields:
            old = fields[name]
            fields[name] = (old if isinstance(old, list) else [old]) + [value]
        else:
            fields[name] = value
    stamp, provider, execution = node('TimeCreated'), node('Provider'), node('Execution')
    return {'event_id': text('EventID'), 'record_id': text('EventRecordID'), 'channel': text('Channel'),
            'computer': text('Computer'), 'provider': provider.get('Name') if provider is not None else None,
            'timestamp': stamp.get('SystemTime') if stamp is not None else None,
            'process_id': fields.get('ProcessId', fields.get('NewProcessId')),
            'provider_process_id': execution.get('ProcessID') if execution is not None else None,
            'process_guid': fields.get('ProcessGuid'), 'data': fields}


def normalize_event(event):
    if not isinstance(event, dict) or not isinstance(event.get('data', {}), dict):
        raise ValueError('Event JSON must be an object with a data mapping')
    result = dict(event)
    stamp = event.get('timestamp')
    result['timestamp_utc'] = None
    if stamp:
        try:
            parsed = datetime.fromisoformat(str(stamp).replace('Z', '+00:00'))
            if parsed.tzinfo is not None:
                result['timestamp_utc'] = parsed.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass
    result['correlation_key'] = ('sysmon:' + str(event['process_guid']).lower()) if event.get('process_guid') else None
    return result


def parse_event_file(path, cfg, file_format=None):
    from defusedxml import ElementTree as ET
    path = Path(path)
    if path.stat().st_size > cfg['max_file_bytes']:
        raise ValueError('Event file exceeds byte limit')
    fmt = file_format or path.suffix.lower()
    events, errors, truncated = [], [], False
    def consume(records):
        nonlocal truncated
        for index, value in enumerate(records):
            if index >= cfg['max_events']:
                truncated = True
                break
            try:
                if isinstance(value, bytes):
                    value = value.decode('utf-8-sig')
                if isinstance(value, str):
                    value = event_xml(value) if value.lstrip().startswith('<') else json.loads(value)
                events.append(dict(normalize_event(value), source_record=index))
            except Exception as exc:
                errors.append({'record': index, 'error': f'{type(exc).__name__}: {exc}'})
    if fmt == '.evtx':
        from Evtx.Evtx import Evtx
        with Evtx(str(path)) as log:
            consume(record.xml() for record in log.records())
    elif fmt == '.xml':
        def xml_records():
            for _, element in ET.iterparse(str(path), events=('end',)):
                if element.tag.rsplit('}', 1)[-1] == 'Event':
                    yield ET.tostring(element, encoding='unicode')
                    element.clear()
        consume(xml_records())
    elif fmt == '.jsonl':
        with path.open(encoding='utf-8-sig') as stream:
            consume(line for line in stream if line.strip())
    else:
        raise ValueError('Supported event formats are .evtx, .xml and normalized .jsonl')
    return {'status': 'partial' if errors or truncated else 'completed', 'events': events,
            'errors': errors, 'truncated': truncated,
            'note': 'ProcessGuid joins Sysmon events; PID alone does not establish a cross-source process identity'}


def run_forensics(inputs, cfg, output):
    import hashlib
    import shutil
    from core.evidence import write_json
    from core.process_runner import run_bounded
    results = []
    root = Path(output) / 'forensics'
    root.mkdir(exist_ok=True)
    for index, (path, file_format) in enumerate(inputs):
        directory = root / f'{index:04d}'
        directory.mkdir()
        path = Path(path)
        entry = {'input_name': path.name, 'format': file_format}
        results.append(entry)
        if path.stat().st_size > cfg['max_file_bytes']:
            entry.update(status='skipped_limit', error='Event file exceeds byte limit')
            continue
        source = directory / 'source.bin'
        shutil.copyfile(path, source)
        entry.update(sha256=hashlib.sha256(source.read_bytes()).hexdigest(), source=str(source.relative_to(output)))
        write_json(directory / 'options.json', cfg)
        execution = run_bounded([sys.executable, str(Path(__file__).resolve()), '--worker', str(source),
                                 '--format', file_format, '--output', str(directory),
                                 '--options', str(directory / 'options.json')], directory,
                                timeout=cfg['timeout_seconds'], max_output_bytes=cfg['max_output_bytes'])
        entry.update(status=execution['status'], execution=execution)
        result_path = directory / 'result.json'
        if result_path.is_file() and result_path.stat().st_size <= cfg['max_output_bytes']:
            entry['result'] = json.loads(result_path.read_text())
            if entry['status'] == 'completed':
                entry['status'] = entry['result']['status']
        elif entry['status'] == 'completed':
            entry.update(status='failed', error='Missing event result')
    write_json(Path(output) / 'forensics.json', results)
    timeline = []
    for index, entry in enumerate(results):
        for event_index, event in enumerate(entry.get('result', {}).get('events', [])):
            timeline.append({'source': f'forensics.json#/{index}/result/events/{event_index}', **event})
    timeline.sort(key=lambda e: (e.get('timestamp_utc') is None, e.get('timestamp_utc') or '', e['source']))
    with (Path(output) / 'forensic_timeline.jsonl').open('w', encoding='utf-8') as stream:
        for event in timeline:
            stream.write(json.dumps(event, ensure_ascii=True) + '\n')
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', required=True)
    parser.add_argument('--format', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--options', required=True)
    args = parser.parse_args()
    try:
        cfg = json.loads(Path(args.options).read_text())
        if args.format == '.zip':
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            from core.intake import inspect_archive, extract_member
            limits = {'max_archive_bytes': cfg['max_file_bytes'], 'max_member_bytes': cfg['max_file_bytes'],
                      'max_total_bytes': cfg['max_file_bytes'], 'max_members': 64, 'max_ratio': 1000}
            inventory = inspect_archive(args.worker, limits)
            aggregate = {'status': 'completed', 'events': [], 'members': [], 'errors': [], 'truncated': False}
            candidates = [m for m in inventory['members'] if Path(m['name']).suffix.lower() in ('.evtx', '.xml', '.jsonl') and not m['directory']]
            if not candidates:
                raise ValueError('EVTX bundle has no supported event-log members')
            for index, member in enumerate(candidates):
                remaining = cfg['max_events'] - len(aggregate['events'])
                if remaining <= 0:
                    aggregate.update(status='partial', truncated=True)
                    break
                try:
                    path, metadata = extract_member(args.worker, member['name'], Path(args.output) / f'member-{index}',
                                                    limits, os.environ.get(cfg['archive_password_env']))
                    result = parse_event_file(path, dict(cfg, max_events=remaining), Path(member['name']).suffix.lower())
                    aggregate['members'].append(metadata)
                    aggregate['events'].extend(dict(e, archive_member=member['name']) for e in result['events'])
                    if result['status'] != 'completed':
                        aggregate.update(status='partial', truncated=aggregate['truncated'] or result['truncated'])
                        aggregate['errors'].extend(result['errors'])
                except Exception as exc:
                    aggregate['status'] = 'partial'
                    aggregate['errors'].append({'member': member['name'], 'error': f'{type(exc).__name__}: {exc}'})
            result = aggregate
        else:
            result = parse_event_file(args.worker, cfg, args.format)
        Path(args.output, 'result.json').write_text(json.dumps(result, ensure_ascii=True), encoding='utf-8')
    except Exception as exc:
        Path(args.output, 'result.json').write_text(json.dumps({'status': 'failed', 'error': f'{type(exc).__name__}: {exc}'}))
        raise SystemExit(1)
