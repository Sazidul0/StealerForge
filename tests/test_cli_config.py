import hashlib
import json
import subprocess
import sys
from pathlib import Path
import pytest
import yaml

from core.config import credential, load_config
from core.evidence import artifact_manifest

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args, cwd=None):
    return subprocess.run([sys.executable, str(ROOT / 'main.py'), *map(str, args)],
                          cwd=cwd, capture_output=True, text=True, timeout=30)


def test_help_and_setup(tmp_path):
    help_result = run_cli('--help', cwd=tmp_path)
    assert help_result.returncode == 0
    assert '--static-only' in help_result.stdout
    check = run_cli('--check', cwd=tmp_path)
    assert check.returncode == 0, check.stderr
    assert json.loads(check.stdout)['local_setup'] == 'ok'


def test_offline_end_to_end(pe_sample, cape_report, tmp_path):
    cape_report['target'] = {'file': {'sha256': hashlib.sha256(pe_sample.read_bytes()).hexdigest()}}
    raw = tmp_path / 'report.json'
    raw.write_text(json.dumps(cape_report))
    output = tmp_path / 'runs'
    result = run_cli('-f', pe_sample, '--skip-cape', raw, '--offline-llm', '--output', output, '--artifact', pe_sample)
    assert result.returncode == 0, result.stdout + result.stderr
    run = next(output.iterdir())
    state = json.loads((run / 'run_status.json').read_text())
    assert state['status'] == 'evidence_ready'
    assert state['rule_validation'] == 'no_rules'
    evidence = json.loads((run / 'evidence.json').read_text())
    assert any(r['kind'] == 'extracted_config' for r in evidence['records'])
    assert any(r['kind'] == 'api_call' for r in evidence['records'])
    assert (run / 'raw_cape_report.json').read_bytes() == raw.read_bytes()
    manifest = json.loads((run / 'manifest.json').read_text())
    for item in manifest:
        path = run / item['path']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256']
    assert not (run / 'Threat_Intel_and_SOC_Rules.md').exists()
    assert (run / 'Evidence_Report.md').exists()


def test_static_only_invalid_rule_returns_review(pe_sample, tmp_path):
    report = tmp_path / 'analyst.md'
    report.write_text('Analysis [E0000001]\n\n```yara\nrule nope {strings: $a="NEVER_PRESENT" condition:$a}\n```\n')
    output = tmp_path / 'runs'
    result = run_cli('-f', pe_sample, '--static-only', '--report-markdown', report, '--output', output)
    assert result.returncode == 2, result.stderr
    run = next(output.iterdir())
    status = json.loads((run / 'run_status.json').read_text())
    assert status['status'] == 'needs_review'
    assert status['rule_validation'] == 'checks_failed'


def test_sample_report_mismatch_fails(pe_sample, tmp_path):
    report = tmp_path / 'report.json'
    report.write_text(json.dumps({'target': {'file': {'sha256': '0'*64}}}))
    output = tmp_path / 'runs'
    result = run_cli('-f', pe_sample, '--cape-report', report, '--output', output)
    assert result.returncode == 1
    run = next(output.iterdir())
    assert json.loads((run / 'run_status.json').read_text())['status'] == 'failed'
    assert (run / 'manifest.json').exists()


def test_relative_paths_and_env_precedence(tmp_path, monkeypatch):
    cfg = yaml.safe_load((ROOT / 'config.yaml').read_text())
    cfg['static_analysis']['yara_rules_path'] = str(ROOT / 'rules/local_stealer_hunting.yar')
    cfg['output']['directory'] = 'my-output'
    path = tmp_path / 'config.yaml'
    path.write_text(yaml.safe_dump(cfg))
    loaded = load_config(path)
    assert loaded['output']['directory'] == str(tmp_path / 'my-output')
    monkeypatch.setenv('CAPE_API_TOKEN', 'environment-token')
    assert credential({'api_token': 'legacy-token'}, 'api_token', 'api_token_env', 'CAPE_API_TOKEN') == 'environment-token'


@pytest.mark.parametrize('section,key,value', [
    ('cape', 'poll_interval_seconds', 0), ('llm', 'use_api', 'false'),
    ('static_analysis', 'min_string_length', 201), ('token_maximizer', 'target_token_budget', 1),
    ('llm', 'input_token_budget', 200000), ('cape', 'timeout_seconds', float('nan')),
])
def test_bad_config_rejected(tmp_path, section, key, value):
    cfg = yaml.safe_load((ROOT / 'config.yaml').read_text())
    cfg[section][key] = value
    path = tmp_path / 'config.yaml'
    path.write_text(yaml.safe_dump(cfg))
    with pytest.raises(ValueError):
        load_config(path)


def test_managed_invalid_input_fails_before_provisioning(tmp_path):
    result = run_cli('--managed', '-f', tmp_path / 'missing.exe', '--lab-storage', tmp_path / 'lab')
    assert result.returncode == 1
    assert 'regular file' in result.stderr
    assert not (tmp_path / 'lab').exists()


def test_managed_prepare_cli_dispatch_without_native_dependencies(monkeypatch):
    from main import main
    from core.managed_lab import ManagedLab
    calls = []
    monkeypatch.setattr(ManagedLab, 'run', lambda self, *a, **kw: calls.append((a, kw)) or 0)
    monkeypatch.setattr('core.config.missing_dependencies', lambda: ['native-parser-intentionally-absent'])
    assert main(['--managed-prepare']) == 0
    assert calls == [((None,), {'prepare_only': True, 'cleanup_only': False, 'output': None, 'guest_paths': [], 'reanalyze': None})]


def test_managed_modes_reject_ambiguous_inputs(tmp_path):
    sample = tmp_path / 'sample.bin'
    sample.write_bytes(b'benign')
    for flags in [('--managed-prepare', '-f', str(sample)),
                  ('--managed', '-f', str(sample), '--ephemeral-artifacts')]:
        result = run_cli(*flags)
        assert result.returncode == 1
    assert run_cli('--managed', '--static-only', '-f', sample).returncode == 2
