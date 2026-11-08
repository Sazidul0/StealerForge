import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from core.config import load_config
from core.context_maximizer import ContextWindowMaximizer
from core.evidence import build_evidence
from core.local_engines import parser_candidates, pe_kind, run_local_engines
from core.process_runner import run_bounded
from core.engine_worker import memory_priority

ROOT = Path(__file__).resolve().parents[1]
ENGINE_PYTHON = Path(os.environ.get('STEALERFORGE_ENGINE_PYTHON', ROOT / '.venv-engines/bin/python'))


def test_config_keeps_virtualenv_interpreter_path(tmp_path):
    import yaml
    environment = tmp_path / 'engines' / 'bin'
    environment.mkdir(parents=True)
    interpreter = environment / 'python'
    interpreter.symlink_to(sys.executable)
    config = tmp_path / 'config.yaml'
    config.write_text(yaml.safe_dump({
        'static_analysis': {'yara_rules_path': str(ROOT / 'rules/local_stealer_hunting.yar')},
        'local_analysis': {'python_path': 'engines/bin/python', 'cape_yara_path': 'signatures'}}))
    loaded = load_config(config)['local_analysis']
    assert loaded['python_path'] == str(interpreter)
    assert loaded['cape_yara_path'] == str(tmp_path / 'signatures')


def test_parser_selection_matches_metadata_not_rule_names():
    hits = [{'rule': 'a_random_name', 'meta': {'cape_type': 'Rhadamanthys Payload'}},
            {'rule': 'RedLine', 'meta': {}}, {'meta': {'cape_type': 'Unknown Config'}},
            {'meta': {'cape_type': 42}}]
    assert parser_candidates(hits, ['Rhadamanthys', 'RedLine']) == ['Rhadamanthys']


def test_late_allocations_take_priority_over_emulator_support_mappings():
    from types import SimpleNamespace
    regions = [SimpleNamespace(base=0x1000, tag='emu.module.kernel32.0x1000'),
               SimpleNamespace(base=0x2000, tag='emu.stack.0x2000'),
               SimpleNamespace(base=0x400000, tag='emu.module.input.0x400000'),
               SimpleNamespace(base=0x8000, tag='api.VirtualAlloc.0x8000')]
    selected = sorted(regions, key=lambda r: memory_priority(r, 0x400000))[:2]
    assert [r.base for r in selected] == [0x8000, 0x400000]


def test_pe_kind_and_non_pe(pe_sample, tmp_path):
    assert pe_kind(pe_sample) == {'pe': True, 'dotnet': False, 'upx': False}
    path = tmp_path / 'data.bin'
    path.write_bytes(b'not a PE')
    assert not pe_kind(path)['pe']


def test_bounded_process_timeout_and_output_limit(tmp_path):
    result = run_bounded([sys.executable, '-c', 'import time; time.sleep(10)'], tmp_path / 'timeout', timeout=0.1)
    assert result['status'] == 'timeout'
    result = run_bounded([sys.executable, '-c', 'print("a" * 20000)'], tmp_path / 'large', max_output_bytes=1024)
    assert result['status'] == 'output_limit'
    assert (tmp_path / 'large/stdout.log').stat().st_size <= 1024


def test_missing_worker_is_recorded(pe_sample, tmp_path):
    cfg = load_config(ROOT / 'config.yaml')['local_analysis']
    cfg['python_path'] = '/nonexistent/python'
    summary, generated, collection = run_local_engines([pe_sample], cfg, tmp_path, 100000)
    assert summary['status'] == 'partial'
    assert not generated
    assert any(s['status'] == 'unavailable' for s in summary['stages'])


def test_emulation_evidence_is_not_cape_observation():
    local = {'stages': [{'engine': 'speakeasy', 'status': 'partial', 'input_sha256': 'a'*64,
                        'result': {'coverage_warnings': ['instruction budget'],
                                   'report_data': {'entry_points': [{'apis': [
                                       {'api_name': 'kernel32.CryptUnprotectData', 'args': ['fake'], 'ret_val': '0x0'}]}]}}}]}
    evidence = build_evidence({}, [], {'info': {'analysis_mode': 'local'}}, local_results=local)
    emulated = next(r for r in evidence['records'] if r['kind'] == 'emulated_api_call')
    assert emulated['evidence_class'] == 'emulated_behavior_not_observed_windows_execution'
    assert emulated['priority'] == 1
    assert not any(r['kind'] == 'api_call' for r in evidence['records'])
    assert 'local_analysis.json#/stages/0' in emulated['source']
    dossier = ContextWindowMaximizer().build_from_evidence(evidence)
    assert any(r['kind'] == 'emulated_api_call' for r in dossier['records'])


@pytest.mark.skipif(not ENGINE_PYTHON.is_file(), reason='Optional engine environment not installed')
def test_real_optional_engines_on_synthetic_pe(pe_sample, tmp_path):
    cfg = load_config(ROOT / 'config.yaml')['local_analysis']
    cfg.update(python_path=str(ENGINE_PYTHON), emulation_seconds=3, max_instructions=10000,
               max_generated_artifacts=2, max_generated_bytes=1048576, max_region_bytes=524288,
               parser_names=['RedLine'], timeout_seconds=30)
    summary, generated, collection = run_local_engines([pe_sample], cfg, tmp_path, 134217728)
    inventory = next(s for s in summary['stages'] if s['engine'] == 'inventory')
    assert inventory['status'] == 'completed', inventory
    checks = inventory['result']['parser_import_checks']
    assert {c['parser'] for c in checks} >= {'RedLine', 'Vidar', 'Stealc', 'Lumma'}
    assert all(c['status'] == 'importable' for c in checks), checks
    emulation = next(s for s in summary['stages'] if s['engine'] == 'speakeasy')
    assert emulation['status'] in ('completed', 'partial'), emulation
    assert 'report_data' in emulation['result'], emulation
    assert any(s['engine'] == 'cape_parser' and s['status'] == 'completed' for s in summary['stages']), summary
    assert generated
    assert all(p.is_file() for p in generated)
    assert all(c['parent_sha256'] for c in collection)


@pytest.mark.skipif(not ENGINE_PYTHON.is_file(), reason='Optional engine environment not installed')
def test_vidar_extraction_from_synthetic_configuration(tmp_path):
    # Inert XOR-encoded configuration bytes, not executable code or a real sample.
    blob = bytearray(2048)
    key = bytes(range(1, 17))
    blob[:16] = key
    def field(offset, length_offset, value):
        blob[offset:offset + len(value)] = bytes(b ^ key[i % 16] for i, b in enumerate(value))
        blob[length_offset] = len(value)
    field(0x10, 0x30, b'1.8')
    field(0x31, 0x71, b'SYNTHETIC')
    field(0x72, 0x72 + 0x100, b'https://example.invalid/test')
    sample = tmp_path / 'synthetic-config.bin'
    sample.write_bytes(blob)
    options = tmp_path / 'options.json'
    options.write_text(json.dumps({'parser_name': 'Vidar', 'max_file_bytes': 4096}))
    directory = tmp_path / 'worker'
    execution = run_bounded([str(ENGINE_PYTHON), str(ROOT / 'core/engine_worker.py'), 'cape_parser',
                             '--sample', str(sample), '--output', str(directory), '--options', str(options)],
                            directory, timeout=30)
    assert execution['status'] == 'completed', execution
    result = json.loads((directory / 'result.json').read_text())
    assert result['config_found'], result
    assert result['config']['cncs'] == ['https://example.invalid/test']
    assert result['config']['version'] == '1.8'


@pytest.mark.skipif(not ENGINE_PYTHON.is_file(), reason='Optional engine environment not installed')
def test_worker_yara_and_invalid_parser(pe_sample, tmp_path):
    rules = tmp_path / 'rules'
    rules.mkdir()
    (rules / 'ok.yara').write_text('rule Synthetic { meta: cape_type="RedLine Payload" condition: true }')
    (rules / 'broken.yar').write_text('this is not yara')
    options = tmp_path / 'options.json'
    options.write_text(json.dumps({'rules_path': str(rules), 'max_file_bytes': 134217728,
                                   'yara_timeout_seconds': 1}))
    directory = tmp_path / 'scan'
    result = subprocess.run([str(ENGINE_PYTHON), str(ROOT / 'core/engine_worker.py'), 'cape_yara',
                             '--sample', str(pe_sample), '--output', str(directory), '--options', str(options)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    data = json.loads((directory / 'result.json').read_text())
    assert data['status'] == 'partial'
    assert data['matches'][0]['rule'] == 'Synthetic'
    assert data['errors']
    options.write_text(json.dumps({'parser_name': '../escape', 'max_file_bytes': 134217728}))
    result = subprocess.run([str(ENGINE_PYTHON), str(ROOT / 'core/engine_worker.py'), 'cape_parser',
                             '--sample', str(pe_sample), '--output', str(directory), '--options', str(options)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 1
    assert json.loads((directory / 'result.json').read_text())['status'] == 'failed'


@pytest.mark.skipif(not Path('/opt/assets/manifest.json').is_file(), reason='Requires bundled container assets')
def test_container_cli_with_bundled_engines(pe_sample, tmp_path):
    import yaml
    cfg = yaml.safe_load((ROOT / 'container/config.yaml').read_text())
    cfg['static_analysis']['yara_rules_path'] = str(ROOT / 'rules/local_stealer_hunting.yar')
    cfg['local_analysis'].update(max_generated_artifacts=1, max_generated_bytes=1048576,
                                 max_region_bytes=524288, emulation_seconds=3, max_instructions=10000,
                                 parser_names=['RedLine'])
    config = tmp_path / 'engines.yaml'
    config.write_text(yaml.safe_dump(cfg))
    runs = tmp_path / 'runs'
    execution = subprocess.run([sys.executable, str(ROOT / 'main.py'), '-c', str(config),
                                '-f', str(pe_sample), '--static-only', '--offline-llm', '--output', str(runs)],
                               capture_output=True, text=True, timeout=240)
    assert execution.returncode in (0, 2), execution.stdout + execution.stderr
    output = next(runs.iterdir())
    local = json.loads((output / 'local_analysis.json').read_text())
    inventory = next(s for s in local['stages'] if s['engine'] == 'inventory')
    assert inventory['status'] == 'completed', inventory
    emulation = next(s for s in local['stages'] if s['engine'] == 'speakeasy')
    assert 'report_data' in emulation.get('result', {}), emulation
    assert local['generated_artifact_count'] == 1
    assert any(s['engine'] == 'cape_parser' and s['status'] == 'completed' for s in local['stages'])
    scans = [s for s in local['stages'] if s['engine'] == 'cape_yara']
    assert scans and all(s.get('result', {}).get('rules_files_scanned', 0) > 0 for s in scans), scans
    from core.evidence import sha256_file
    digest = sha256_file(pe_sample)
    enrichment = json.loads((output / 'enrichment.json').read_text())
    original = [s for s in enrichment if s.get('artifact_sha256') == digest]
    assert {s['tool'] for s in original} == {'capa', 'floss'}
    for result in original:
        assert result['status'] == 'completed', (result, (output / result['output']).with_name('stderr.log').read_text())
    assert (output / 'Evidence_Report.md').is_file()
    assert (output / 'cape_cti_telemetry.json').is_file()
    assert (output / 'threat_intel_report.md').is_file()
    assert not list(output.rglob('*.bin'))
    assert json.loads((output / 'run_status.json').read_text())['artifact_retention'] == 'ephemeral'
    assert 'data' not in emulation['result']['report_data']
    assert (output / 'claude_maximized_prompt.txt').is_file()
    upx = subprocess.run(['/opt/assets/upx', '--version'], capture_output=True, text=True, timeout=10)
    assert upx.returncode == 0 and '5.3.0' in upx.stdout


@pytest.mark.skipif(not ENGINE_PYTHON.is_file(), reason='Optional engine environment not installed')
@pytest.mark.parametrize('arch', ['x86', 'amd64'])
def test_explicit_shellcode_with_real_emulator(tmp_path, arch):
    sample = tmp_path / 'return.bin'
    sample.write_bytes(b'\xc3')  # A harmless RET, never executed natively.
    cfg = load_config(ROOT / 'config.yaml')['local_analysis']
    cfg.update(python_path=str(ENGINE_PYTHON), shellcode_arch=arch, emulation_seconds=2,
               max_instructions=1000, max_generated_artifacts=1,
               max_generated_bytes=524288, max_region_bytes=524288, timeout_seconds=30)
    summary, _, _ = run_local_engines([sample], cfg, tmp_path, 1048576)
    result = next(s for s in summary['stages'] if s['engine'] == 'speakeasy')
    assert result['result']['report_data']['entry_points'], result
    assert 'data' not in result['result']['report_data']


def test_dotnet_user_string_heap_parser_handles_short_and_long_entries():
    from core.engine_worker import user_strings
    def entry(text):
        data = text.encode('utf-16-le') + b'\x00'
        size = len(data)
        prefix = bytes([size]) if size < 0x80 else bytes([0x80 | size >> 8, size & 0xFF])
        return prefix + data
    long_text = 'C:\\Users\\artem\\' + 'x' * 100
    heap = b'\x00' + entry('127.0.0.1:1912') + b'\x01\x00' + entry(long_text) + entry('net.tcp://')
    assert user_strings(heap) == ['127.0.0.1:1912', long_text, 'net.tcp://']


def test_dotnet_metadata_becomes_chunked_prioritised_evidence(cape_report):
    from core.evidence import build_evidence
    strings = ['plain %d' % i for i in range(25)] + ['https://api.ip.sb/ip']
    local = {'stages': [{'engine': 'dotnet_metadata', 'status': 'completed', 'input_sha256': 'a' * 64,
                         'result': {'status': 'completed', 'assembly': {'name': 'RuntimeHost'}, 'types': ['A', 'B'],
                                    'user_strings': strings, 'pinvoke': [{'module': 'kernel32.dll', 'function': 'CreateRemoteThread'}],
                                    'user_string_count': len(strings)}}]}
    evidence = build_evidence({}, [], cape_report, local_results=local)
    kinds = [(r['kind'], r['priority']) for r in evidence['records'] if r['kind'].startswith('dotnet_')]
    assert ('dotnet_metadata', 1) in kinds and ('dotnet_type', 2) in kinds
    assert [p for k, p in kinds if k == 'dotnet_user_string'] == [2, 1]
