"""Deterministic CTI exports. Findings retain their evidence class and provenance."""
import json
import re

from core.evidence import write_json
from core.reporting import cell


def reference(record):
    return {key: record[key] for key in ('id', 'source', 'artifact_sha256', 'evidence_class') if key in record}


def build_telemetry(initial, evidence, state):
    records = evidence['records']
    telemetry = {
        'schema_version': '1.0',
        'analysis': {key: state[key] for key in ('status', 'error', 'started_at_utc', 'finished_at_utc', 'analysis_mode', 'versions', 'artifact_retention')
                     if key in state},
        'sample': {key: initial[key] for key in ('filename', 'hashes', 'size_bytes', 'overall_entropy',
                                               'pefile_analysis', 'lief_analysis') if key in initial},
        'classification': {'attribution': 'unconfirmed', 'matches': [], 'reported_families': []},
        'configurations': [], 'capabilities': [], 'attack': [],
        'behavior': {'emulated': [], 'cape': []}, 'strings': [], 'engines': [],
        'artifacts': [], 'coverage': evidence['coverage'],
        'integration_note': 'Versioned project schema; MISP/OpenCTI require a mapping or adapter. '
                            'Empty findings are not a clean verdict.',
    }
    mappings = {}
    for record in records:
        kind, data = record['kind'], record['data']
        item = dict(reference(record), data=data)
        if kind == 'local_yara_match':
            telemetry['classification']['matches'].append(item)
        elif kind == 'family_detection':
            telemetry['classification']['reported_families'].append(item)
        elif kind in ('local_config', 'extracted_config'):
            telemetry['configurations'].append(dict(reference(record),
                parser=data.get('parser') if kind == 'local_config' else None,
                origin='local_parser' if kind == 'local_config' else 'cape',
                config=data.get('config') if kind == 'local_config' else data,
                interpretation='candidate_extraction'))
        elif kind == 'static_capability':
            telemetry['capabilities'].append(item)
            meta = data.get('meta', {})
            for attack in meta.get('att&ck', meta.get('attack', [])):
                if not isinstance(attack, dict) or not re.fullmatch(r'T\d{4}(?:\.\d{3})?', attack.get('id', '')):
                    continue
                key = (attack['id'], attack.get('tactic', ''))
                mapping = mappings.setdefault(key, {
                    **{k: attack.get(k, '') for k in ('id', 'tactic', 'technique', 'subtechnique')},
                    'evidence_class': 'static_capability_not_observed_execution', 'evidence': [],
                })
                mapping['evidence'].append(reference(record))
        elif kind in ('emulated_api_call', 'emulation_activity'):
            telemetry['behavior']['emulated'].append(dict(item, kind=kind,
                **{k: record[k] for k in ('sequence', 'entry_point', 'process_key') if k in record}))
        elif kind in ('api_call', 'process_tree') or kind.startswith(('host_', 'network_')):
            telemetry['behavior']['cape'].append(dict(item, kind=kind,
                **{k: record[k] for k in ('sequence', 'pid', 'timestamp', 'process_key') if k in record}))
        elif kind == 'decoded_string':
            telemetry['strings'].append(item)
        elif kind in ('local_engine_status', 'enrichment'):
            # Large raw capa/FLOSS objects already live in enrichment.json.
            telemetry['engines'].append(dict(reference(record),
                data={k: v for k, v in data.items() if k != 'result'}))
        elif kind == 'artifact_collection':
            telemetry['artifacts'].append(item)
    telemetry['attack'] = [mappings[key] for key in sorted(mappings)]
    return telemetry


def render_advisory(telemetry):
    sample = telemetry['sample']
    lines = ['# Threat intelligence report', '', '## 1. Executive Triage Summary', '',
             f'Input: {cell(sample.get("filename", "unknown"), 500)}; size: {sample.get("size_bytes", "unknown")} bytes.', '',
             f'Analysis status: **{cell(telemetry["analysis"].get("status", "unknown"))}**.', '',
             'Family attribution: **unconfirmed**. Signature matches and extracted configurations are evidence '
             'for analyst review; absence of findings does not establish that an input is harmless.', '']
    for name, digest in sample.get('hashes', {}).items():
        lines.append(f'- {cell(name.upper())}: `{cell(digest)}`')
    lines += ['', 'Coverage:', '']
    for warning in telemetry['coverage'].get('warnings', []):
        lines.append('- ' + cell(warning, 2000))

    def table(title, entries, describe, limit=150):
        lines.extend(['', title, '', '| Evidence | Finding |', '|---|---|'])
        if not entries:
            lines.append('| — | No finding available; inspect engine statuses and coverage. |')
        for entry in entries[:limit]:
            lines.append(f'| {cell(entry.get("id", ""))} | {cell(describe(entry), 2000)} |')
        if len(entries) > limit:
            lines.extend(['', f'Displaying {limit} of {len(entries)} records; the JSON export retains all records.'])

    dump = lambda value: json.dumps(value, ensure_ascii=True, sort_keys=True)
    table('Signature and family evidence', telemetry['classification']['matches'] +
          telemetry['classification']['reported_families'], lambda e: dump(e['data']))
    table('## 2. Extracted Malware Configuration', telemetry['configurations'],
          lambda e: f'{e["origin"]} / {e["parser"] or "unspecified"}: {dump(e["config"])}')
    lines += ['', '## 3. MITRE ATT&CK Behavioral Breakdown', '',
              'The mappings below describe static capabilities, not confirmed execution.', '',
              '| Tactic | Technique | Evidence |', '|---|---|---|']
    for mapping in telemetry['attack']:
        lines.append(f'| {cell(mapping["tactic"])} | {cell(mapping["id"])}: '
                     f'{cell(mapping["technique"])} / {cell(mapping["subtechnique"])} | '
                     f'{cell(", ".join(r["id"] for r in mapping["evidence"]), 2000)} |')
    if not telemetry['attack']:
        lines.append('| — | No supported mapping available | — |')
    table('Detected capabilities', telemetry['capabilities'], lambda e: e['data'].get('name', 'unnamed'))
    lines += ['', '## 4. Dynamic Emulation Telemetry', '',
              'Modeled API activity and CAPE guest telemetry are kept separate. Inspect API return values '
              'before interpreting an attempted operation as successful.']
    table('Emulated activity', telemetry['behavior']['emulated'], lambda e: dump(e['data']))
    table('CAPE guest activity (when supplied)', telemetry['behavior']['cape'], lambda e: dump(e['data']))
    # Keep decoded/stack/tight/language strings ahead of static text; mark this as a heuristic.
    ranked = sorted(telemetry['strings'], key=lambda e: (
        e['data'].get('category', '') == 'static_strings',
        not bool(re.search(r'https?://|hkey_|software\\|mutex|wallet|telegram|discord', dump(e['data']), re.I))))
    table('## 5. Deobfuscated Strings Appendix', ranked,
          lambda e: f'{e["data"].get("category", "unknown")}: {dump(e["data"].get("value"))}')
    lines += ['', 'String ordering is a triage heuristic. Full values, offsets, engine outcomes, and source '
              'references are in `cape_cti_telemetry.json` and `evidence.json`. '
              'Displayed values are escaped and may be truncated to 2,000 characters.', '']
    return '\n'.join(lines)


def write_cti(output, initial, evidence, state):
    telemetry = build_telemetry(initial, evidence, state)
    write_json(output / 'cape_cti_telemetry.json', telemetry)
    (output / 'threat_intel_report.md').write_text(render_advisory(telemetry), encoding='utf-8')
