"""Optional local capability/string tools. No shell and no sample execution."""
import json
import shutil
from pathlib import Path

from core.evidence import sha256_file
from core.process_runner import run_bounded


def run_enrichment(artifacts, cfg, output_dir, representations=None):
    results = []
    representations = representations or {}
    artifacts = list({sha256_file(path): path for path in artifacts}.values())
    for tool in ('capa', 'floss'):
        executable = cfg.get(f'{tool}_path')
        if not executable:
            continue
        resolved = shutil.which(executable)
        if not resolved:
            results.append({'tool': tool, 'status': 'unavailable'})
            continue
        for artifact in artifacts:
            digest = sha256_file(artifact)
            representation = representations.get(digest, 'file')
            # A mapped image/heap region cannot safely be treated as an on-disk PE.
            if representation == 'emulator_memory_region_not_reconstructed_PE':
                results.append({'tool': tool, 'artifact_sha256': digest, 'status': 'unsupported',
                                'note': 'Raw emulator region requires reconstruction or explicit code architecture; YARA/config scanning still applies'})
                continue
            shellcode = representation.removeprefix('shellcode_') if representation.startswith('shellcode_') else ''
            if not shellcode:
                from core.local_engines import pe_kind
                kind = pe_kind(artifact)
                if not kind['pe'] or (tool == 'floss' and kind['dotnet']):
                    results.append({'tool': tool, 'artifact_sha256': digest, 'status': 'unsupported',
                                    'note': 'This pipeline routes PE files to capa and native PE files to FLOSS'})
                    continue
            folder = Path(output_dir) / 'enrichment' / f'{tool}_{digest}'
            folder.mkdir(parents=True, exist_ok=True)
            stdout = folder / 'stdout.log'
            entry = {'tool': tool, 'artifact_sha256': digest, 'output': str(stdout.relative_to(output_dir))}
            results.append(entry)
            try:
                command = [resolved, '-j']
                if shellcode:
                    command += ['-f', 'sc32' if shellcode == 'x86' else 'sc64']
                if tool == 'capa' and cfg.get('capa_rules_path'):
                    command += ['-r', cfg['capa_rules_path']]
                if tool == 'capa' and cfg.get('capa_signatures_path'):
                    command += ['-s', cfg['capa_signatures_path']]
                execution = run_bounded(command + [str(Path(artifact).resolve())], folder,
                                        timeout=cfg.get('timeout_seconds', 120),
                                        max_output_bytes=cfg.get('max_output_bytes', 16777216),
                                        memory_mb=cfg.get('memory_mb', 2048))
                entry['execution'] = execution
                if execution['status'] != 'completed':
                    entry['status'] = execution['status']
                elif stdout.stat().st_size > cfg.get('max_output_bytes', 16777216):
                    entry.update(status='output_limit', note='Output retained on disk, not loaded into evidence')
                else:
                    entry.update(status='completed', result=json.loads(stdout.read_text(encoding='utf-8')))
            except (OSError, ValueError) as exc:
                entry.update(status='failed', error=str(exc))
    return results
