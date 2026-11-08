import hashlib
import json
from pathlib import Path

import pytest

from core.workspace import RunWorkspace
from test_cli_config import run_cli


def test_ephemeral_cli_exports_reports_but_no_imported_bytes(pe_sample, tmp_path):
    output = tmp_path / 'runs'
    result = run_cli('-f', pe_sample, '--static-only', '--ephemeral-artifacts', '--artifact', pe_sample,
                     '--output', output)
    assert result.returncode == 0, result.stdout + result.stderr
    run = next(output.iterdir())
    assert (run / 'cape_cti_telemetry.json').is_file()
    assert (run / 'threat_intel_report.md').is_file()
    assert not (run / 'artifacts').exists()
    collection = json.loads((run / 'artifact_collection.json').read_text())
    assert collection and all(e['retained_after_run'] is False for e in collection)
    assert json.loads((run / 'run_status.json').read_text())['artifact_retention'] == 'ephemeral'
    for entry in json.loads((run / 'manifest.json').read_text()):
        assert hashlib.sha256((run / entry['path']).read_bytes()).hexdigest() == entry['sha256']


def test_scratch_payloads_and_disguised_files_are_never_published(tmp_path):
    workspace = RunWorkspace(tmp_path / 'export', False, str(tmp_path))
    scratch = workspace.path
    (scratch / 'artifacts').mkdir()
    (scratch / 'artifacts' / 'payload.json').write_bytes(b'MZ\x00hostile fixture')
    worker = scratch / 'local_engines' / '0000_upx'
    worker.mkdir(parents=True)
    (worker / 'unpacked.bin').write_bytes(b'MZ\x00payload')
    (worker / 'result.json').write_text('{"status":"partial"}')
    (scratch / 'run_status.json').write_text('{"status":"failed"}')
    workspace.finish()
    assert not scratch.exists()
    assert not list(workspace.destination.rglob('*.bin'))
    assert not (workspace.destination / 'artifacts').exists()
    assert (workspace.destination / 'local_engines/0000_upx/result.json').is_file()


@pytest.mark.parametrize('problem', ['symlink', 'quota', 'binary'])
def test_publication_errors_fail_closed_and_clean_scratch(tmp_path, problem):
    workspace = RunWorkspace(tmp_path / 'export', False, str(tmp_path), max_bytes=100)
    scratch = workspace.path
    if problem == 'symlink':
        (scratch / 'run_status.json').symlink_to('/etc/passwd')
    elif problem == 'quota':
        (scratch / 'threat_intel_report.md').write_text('x' * 101)
    else:
        (scratch / 'threat_intel_report.md').write_bytes(b'\x00binary')
    with pytest.raises(ValueError):
        workspace.finish()
    assert not scratch.exists()
    assert json.loads((workspace.destination / 'run_status.json').read_text())['status'] == 'failed'


def test_cli_failure_still_publishes_status_and_removes_scratch(pe_sample, tmp_path):
    import yaml
    from test_cli_config import ROOT
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    config = tmp_path / 'config.yaml'
    config.write_text(yaml.safe_dump({
        'static_analysis': {'yara_rules_path': str(ROOT / 'rules/local_stealer_hunting.yar')},
        'output': {'retain_artifacts': False, 'scratch_directory': str(scratch)}}))
    bad = tmp_path / 'bad.json'
    bad.write_text('{"target":{"file":{"sha256":"wrong"}}}')
    output = tmp_path / 'runs'
    result = run_cli('-c', config, '-f', pe_sample, '--cape-report', bad, '--output', output)
    assert result.returncode == 1
    assert not list(scratch.iterdir())
    run = next(output.iterdir())
    assert json.loads((run / 'run_status.json').read_text())['status'] == 'failed'
    assert (run / 'manifest.json').is_file()
    assert json.loads((run / 'cape_cti_telemetry.json').read_text())['analysis']['status'] == 'failed'


def test_truncated_worker_report_does_not_hide_completed_reports(tmp_path):
    workspace = RunWorkspace(tmp_path / 'export', False, str(tmp_path))
    (workspace.path / 'run_status.json').write_text('{"status":"evidence_ready"}')
    worker = workspace.path / 'local_engines' / '0000_speakeasy'
    worker.mkdir(parents=True)
    (worker / 'result.json').write_text('{"unfinished":')
    omitted = workspace.finish()
    assert len(omitted) == 1
    assert json.loads((workspace.destination / 'run_status.json').read_text())['status'] == 'needs_review'
    assert (workspace.destination / 'report_publication.json').is_file()
