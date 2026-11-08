import subprocess
from types import SimpleNamespace

from core import lab_readiness as readiness


def test_storage_checks_existing_filesystem_without_creating_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(readiness.shutil, 'disk_usage', lambda _: SimpleNamespace(free=34 * readiness.GIB))
    target = tmp_path / 'new' / 'lab-data'
    result = readiness.inspect_storage(target, 80)
    assert result['status'] == 'blocked'
    assert result['free_gib'] == 34
    assert result['filesystem_checked_at'] == str(tmp_path)
    assert not target.exists()


def test_regular_file_cannot_stand_in_for_kvm_device(tmp_path):
    path = tmp_path / 'kvm'
    path.write_bytes(b'')
    assert readiness.inspect_kvm(path)['status'] == 'blocked'
    assert readiness.inspect_kvm(tmp_path / 'missing')['status'] == 'blocked'


def test_available_memory_is_used_not_total_memory(tmp_path):
    path = tmp_path / 'meminfo'
    path.write_text('MemTotal: 20000000 kB\nMemAvailable: 1000000 kB\n')
    assert readiness.inspect_memory(8, path)['status'] == 'blocked'


def test_failed_prerequisites_do_not_launch_probe(tmp_path, monkeypatch):
    monkeypatch.setattr(readiness, 'inspect_kvm', lambda: {'status': 'blocked'})
    monkeypatch.setattr(readiness, 'docker_server', lambda: {'status': 'passed'})
    monkeypatch.setattr(readiness, 'probe_docker_kvm', lambda: (_ for _ in ()).throw(AssertionError('must not run')))
    report = readiness.check_host(tmp_path, minimum_free_gib=1, minimum_available_gib=1, probe=True)
    assert report['status'] == 'blocked'
    assert report['checks']['docker_kvm']['status'] == 'blocked'
    assert report['deployment_status'] == 'not_provisioned_or_validated_by_this_check'


def test_docker_timeout_is_reported_as_blocker(tmp_path, monkeypatch):
    def fail():
        raise subprocess.TimeoutExpired('docker', 20)
    monkeypatch.setattr(readiness, 'docker_server', fail)
    report = readiness.check_host(tmp_path)
    assert report['checks']['docker']['status'] == 'blocked'


def test_probe_uses_existing_image_and_only_kvm_api_query(monkeypatch):
    def run(command, **kwargs):
        assert command[command.index('--pull') + 1] == 'never'
        assert command[command.index('--network') + 1] == 'none'
        assert command[command.index('--device') + 1] == '/dev/kvm'
        assert '0xAE00' in command[-1]
        return SimpleNamespace(returncode=0, stdout='12\n', stderr='')
    monkeypatch.setattr(readiness.subprocess, 'run', run)
    assert readiness.probe_docker_kvm()['status'] == 'passed'
