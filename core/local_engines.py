"""Automated local triage stages. Use a dedicated analysis environment for hostile files."""
import json
import re
import sys
from pathlib import Path

from core.evidence import sha256_file, write_json
from core.process_runner import run_bounded

WORKER = Path(__file__).with_name('engine_worker.py').resolve()


def parser_candidates(matches, available):
    normalized = {re.sub(r'[^a-z0-9]', '', name.lower()): name for name in available}
    names = set()
    for hit in matches:
        cape_type = hit.get('meta', {}).get('cape_type', '')
        if not isinstance(cape_type, str):
            continue
        family = re.sub(r' (?:payload|config|loader|strings)$', '', cape_type, flags=re.I)
        key = re.sub(r'[^a-z0-9]', '', family.lower())
        if key in normalized:
            names.add(normalized[key])
    return sorted(names)


def pe_kind(path):
    import pefile
    try:
        pe = pefile.PE(str(path), fast_load=True)
        try:
            dotnet = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0
            upx = any(s.Name.rstrip(b'\0').upper().startswith(b'UPX') for s in pe.sections)
            return {'pe': True, 'dotnet': dotnet, 'upx': upx}
        finally:
            pe.close()
    except (pefile.PEFormatError, OSError, IndexError):
        return {'pe': False, 'dotnet': False, 'upx': False}


def run_local_engines(inputs, cfg, output_dir, max_file_bytes):
    output_dir = Path(output_dir)
    root = output_dir / 'local_engines'
    root.mkdir(exist_ok=True)
    python = cfg.get('python_path') or sys.executable
    outcomes, generated, collection = [], [], []
    remaining_bytes = cfg['max_generated_bytes']
    seen = {sha256_file(path) for path in inputs}
    if cfg.get('asset_manifest_path'):
        manifest_path = Path(cfg['asset_manifest_path'])
        if manifest_path.is_file() and manifest_path.stat().st_size <= 1048576:
            try:
                manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
                write_json(output_dir / 'engine_assets.json', manifest)
                outcomes.append({'engine': 'asset_provenance', 'status': 'completed', 'result': manifest})
            except (ValueError, OSError) as exc:
                outcomes.append({'engine': 'asset_provenance', 'status': 'failed', 'error': str(exc)})
        else:
            outcomes.append({'engine': 'asset_provenance', 'status': 'failed', 'error': 'Asset manifest unavailable or too large'})

    def stage(engine, sample=None, **options):
        folder = root / f'{len(outcomes):04d}_{engine}'
        folder.mkdir()
        settings = dict(cfg, max_file_bytes=max_file_bytes, **options)
        settings_path = folder / 'options.json'
        write_json(settings_path, settings)
        command = [python, str(WORKER), engine, '--output', str(folder), '--options', str(settings_path)]
        if sample:
            command += ['--sample', str(Path(sample).resolve())]
        execution = run_bounded(command, folder, timeout=cfg['timeout_seconds'],
                                max_output_bytes=cfg['max_output_bytes'], memory_mb=cfg['memory_mb'])
        record = {'engine': engine, 'status': execution['status'], 'execution': execution,
                  'directory': str(folder.relative_to(output_dir)),
                  'input_sha256': sha256_file(sample) if sample else None}
        outcomes.append(record)
        result_file = folder / 'result.json'
        if result_file.is_file() and result_file.stat().st_size <= cfg['max_output_bytes']:
            try:
                record['result'] = json.loads(result_file.read_text(encoding='utf-8'))
                if execution['status'] == 'completed':
                    record['status'] = record['result'].get('status', 'failed')
            except (ValueError, OSError) as exc:
                record.update(status='failed', error=str(exc))
        elif execution['status'] == 'completed':
            record.update(status='failed', error='Worker did not produce a bounded result.json')
        return record, folder

    def accept(path, kind, parent_hash, metadata=None):
        nonlocal remaining_bytes
        entry = {'kind': kind, 'parent_sha256': parent_hash, **(metadata or {})}
        collection.append(entry)
        if not path.is_file() or path.is_symlink():
            entry.update(status='failed', error='Missing or symbolic-link generated artifact')
            return
        size = path.stat().st_size
        digest = sha256_file(path)
        entry.update(sha256=digest, size_bytes=size, path=str(path.relative_to(output_dir)))
        if digest in seen:
            entry['status'] = 'duplicate'
        elif size > max_file_bytes or size > remaining_bytes or len(generated) >= cfg['max_generated_artifacts']:
            entry['status'] = 'skipped_limit'
        else:
            entry['status'] = 'generated'
            seen.add(digest)
            remaining_bytes -= size
            generated.append(path)

    inventory, _ = stage('inventory')
    available = inventory.get('result', {}).get('parsers', [])
    roots = list(dict.fromkeys(Path(p).resolve() for p in inputs))
    if len(roots) > cfg['max_input_artifacts']:
        outcomes.append({'engine': 'input_selection', 'status': 'skipped_limit',
                         'omitted_inputs': len(roots) - cfg['max_input_artifacts']})
    roots = roots[:cfg['max_input_artifacts']]
    for sample in roots:
        identity = sha256_file(sample)
        kind = pe_kind(sample)
        active = sample
        if cfg['upx_path'] and kind['upx']:
            folder = root / f'{len(outcomes):04d}_upx'
            folder.mkdir()
            target = folder / 'unpacked.bin'
            command = [cfg['upx_path'], '-d', '-o', str(target), str(sample)]
            execution = run_bounded(command, folder, timeout=cfg['timeout_seconds'],
                                    max_output_bytes=max(max_file_bytes, cfg['max_output_bytes']), memory_mb=cfg['memory_mb'])
            outcomes.append({'engine': 'upx', 'status': execution['status'], 'input_sha256': identity,
                             'execution': execution, 'directory': str(folder.relative_to(output_dir))})
            if execution['status'] == 'completed' and target.is_file():
                accept(target, 'upx_output', identity)
                if target in generated:
                    active = target
            elif execution['status'] == 'completed':
                outcomes[-1].update(status='failed', error='UPX produced no output')
        else:
            outcomes.append({'engine': 'upx', 'status': 'not_applicable' if not kind['upx'] else 'disabled',
                             'input_sha256': identity, 'note': 'Automatic UPX selection uses PE section-name hints'})
        shellcode_arch = cfg.get('shellcode_arch', '') if sample == roots[0] else ''
        if cfg['speakeasy'] and ((kind['pe'] and not kind['dotnet']) or shellcode_arch):
            record, folder = stage('speakeasy', active,
                                   shellcode_arch=shellcode_arch,
                                   max_dump_bytes=max(0, remaining_bytes),
                                   max_dumps=max(0, cfg['max_generated_artifacts'] - len(generated)))
            result = record.get('result', {})
            report_file = folder / 'report.json'
            if report_file.is_file() and report_file.stat().st_size <= cfg['max_output_bytes']:
                try:
                    result['report_data'] = json.loads(report_file.read_text(encoding='utf-8'))
                except (ValueError, OSError) as exc:
                    record.update(status='partial', report_error=str(exc))
            for artifact in result.get('artifacts', []):
                if artifact.get('status') != 'captured':
                    continue
                path = (folder / artifact['path']).resolve()
                if not path.is_relative_to(folder.resolve()):
                    record.update(status='failed', error='Worker returned a path outside its output directory')
                    continue
                accept(path, 'emulated_memory', sha256_file(active),
                       {'base': artifact.get('base'), 'tag': artifact.get('tag'),
                        'representation': artifact.get('representation')})
        elif kind['dotnet']:
            # Emulation does not run .NET; its metadata (types, P/Invoke, user strings) is the static substitute.
            stage('dotnet_metadata', active)
        else:
            outcomes.append({'engine': 'speakeasy', 'status': 'unsupported' if cfg['speakeasy'] else 'disabled',
                             'input_sha256': identity,
                             'note': 'Local emulation supports native PE inputs; use the Windows VM for .NET and other formats'})
    scan_inputs = list(dict.fromkeys(roots + generated))
    for sample in scan_inputs:
        matches = []
        if cfg['cape_yara_path']:
            record, _ = stage('cape_yara', sample, rules_path=cfg['cape_yara_path'])
            matches = record.get('result', {}).get('matches', [])
        selected = sorted(set(cfg.get('parser_names', [])) | set(parser_candidates(matches, available)))
        if cfg['cape_parsers']:
            if not selected:
                outcomes.append({'engine': 'cape_parser', 'status': 'no_candidate', 'input_sha256': sha256_file(sample),
                                 'note': 'No parser selected by CAPE YARA metadata or explicit parser_names; this is not a clean verdict'})
            if len(selected) > cfg['max_parsers_per_artifact']:
                outcomes.append({'engine': 'cape_parser_selection', 'status': 'skipped_limit',
                                 'input_sha256': sha256_file(sample),
                                 'omitted_parsers': selected[cfg['max_parsers_per_artifact']:]})
            for name in selected[:cfg['max_parsers_per_artifact']]:
                stage('cape_parser', sample, parser_name=name)
    summary = {'schema_version': 1, 'status': 'completed', 'stages': outcomes,
               'generated_artifact_count': len(generated),
               'note': 'Emulator observations and static capabilities do not establish actual Windows behavior or successful theft'}
    if any(r['status'] in ('failed', 'partial', 'timeout', 'output_limit', 'unavailable', 'skipped_limit', 'unsupported') for r in outcomes + collection):
        summary['status'] = 'partial'
    write_json(output_dir / 'local_analysis.json', summary)
    return summary, generated, collection
