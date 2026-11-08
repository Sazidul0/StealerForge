import json
import io
from pathlib import Path
import socket
import shlex
import threading

import pytest

from core.config import load_config
from core.managed_lab import Docker, LABEL, ManagedLab, ROOT, RunResources, WINDOWS_ISO_URL, atomic_json, bind, contained
from managed.qmp import execute


class FakeDocker:
    def __init__(self):
        self.items = {}
        self.calls = []
        self.fail_inspect = False

    def inspect(self, kind, name):
        if self.fail_inspect:
            raise RuntimeError('daemon unavailable')
        return self.items.get((kind, name))

    def call(self, args, **kwargs):
        self.calls.append(args)
        if args[0] == 'rm':
            self.items.pop(('container', args[-1]), None)
        elif args[:2] == ['volume', 'rm']:
            self.items.pop(('volume', args[-1]), None)
        return 0, ''


@pytest.fixture
def resources(tmp_path):
    journals = tmp_path / 'journals'
    journals.mkdir()
    return RunResources(FakeDocker(), journals, tmp_path / 'storage', tmp_path / 'evidence')


def own(resources, kind, suffix):
    name = resources.reserve(kind, suffix)
    labels = {LABEL: resources.run_id}
    resources.docker.items[(kind, name)] = {'Config': {'Labels': labels}} if kind == 'container' else {'Labels': labels}
    return name


def test_cleanup_removes_only_owned_resources_and_keeps_evidence(resources):
    volume = own(resources, 'volume', 'qmp')
    keeper = own(resources, 'container', 'network')
    guest = own(resources, 'container', 'windows')
    (resources.evidence / 'report.json').write_text('{"retained":true}')
    (resources.work / 'disk.qcow2').write_bytes(b'disposable')
    assert resources.cleanup()
    assert not resources.work.exists()
    assert json.loads((resources.evidence / 'report.json').read_text())['retained']
    removals = [c for c in resources.docker.calls if c[0] == 'rm' or c[:2] == ['volume', 'rm']]
    assert removals == [['rm', '-f', guest], ['rm', '-f', keeper], ['volume', 'rm', volume]]
    assert json.loads((resources.evidence / 'managed_run.json').read_text())['cleanup'] == 'completed'


@pytest.mark.parametrize('problem', ['ownership', 'daemon'])
def test_failed_cleanup_keeps_workspace_for_recovery(resources, problem):
    name = own(resources, 'container', 'windows')
    if problem == 'ownership':
        resources.docker.items[('container', name)]['Config']['Labels'][LABEL] = 'another-run'
    else:
        resources.docker.fail_inspect = True
    assert not resources.cleanup()
    assert resources.work.is_dir()
    assert not any(c[0] == 'rm' for c in resources.docker.calls)
    assert resources.state['cleanup_errors']


def test_failed_creation_is_journaled_before_docker_mutation(resources):
    def fail(args, **kwargs):
        saved = json.loads(resources.path.read_text())
        assert saved['resources'][0]['name'] in args
        raise RuntimeError('ambiguous Docker timeout')
    resources.docker.call = fail
    with pytest.raises(RuntimeError):
        resources.start('windows', [], 'image')
    assert resources.state['resources']


def test_recovery_refuses_invalid_resource_identity(resources):
    resources.state['resources'].append({'kind': 'container', 'name': 'unrelated-service'})
    assert not resources.cleanup()
    assert resources.work.exists()
    assert not resources.docker.calls


@pytest.mark.parametrize('output,absent', [
    ('Error: No such container: sf-test', True),
    ('Error response from daemon: No such image: missing:tag', True),
    ('Error response from daemon: get missing: volume missing not found', True),
    ('Cannot connect to the Docker daemon', False),
    ('permission denied while trying to connect to Docker', False),
])
def test_inspect_only_treats_explicit_missing_resource_as_absent(monkeypatch, output, absent):
    docker = Docker()
    monkeypatch.setattr(docker, 'call', lambda *a, **kw: (1, output))
    if absent:
        assert docker.inspect('container', 'sf-test') is None
    else:
        with pytest.raises(RuntimeError, match='cannot assume'):
            docker.inspect('container', 'sf-test')


def test_paths_reject_evidence_escape_and_preserve_spaces(tmp_path):
    with pytest.raises(ValueError):
        contained(tmp_path, '../escape')
    (tmp_path / 'link').symlink_to('/etc/passwd')
    with pytest.raises(ValueError):
        contained(tmp_path, 'link')
    assert bind(tmp_path / 'New Volume', '/base', True)[1].endswith('New Volume,dst=/base,readonly')
    with pytest.raises(ValueError):
        bind(tmp_path / 'has,comma', '/base')


def test_lifecycle_publication_does_not_follow_evidence_symlinks(tmp_path):
    victim = tmp_path / 'outside.txt'
    victim.write_text('untouched')
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    (evidence / 'managed_run.new').symlink_to(victim)
    (evidence / 'managed_run.json').symlink_to(victim)
    atomic_json(evidence / 'managed_run.json', {'cleanup': 'completed'})
    assert victim.read_text() == 'untouched'
    assert not (evidence / 'managed_run.json').is_symlink()
    assert json.loads((evidence / 'managed_run.json').read_text())['cleanup'] == 'completed'


def lab(tmp_path, docker=None):
    cfg = load_config(ROOT / 'config.yaml')['managed_lab']
    cfg.update(storage_directory=str(tmp_path / 'storage'), state_directory=str(tmp_path / 'state'))
    return ManagedLab(cfg, docker or FakeDocker())


def test_failed_guest_boot_preserves_sample_and_cleans_owned_resources(tmp_path, monkeypatch):
    managed = lab(tmp_path)
    managed.journals.mkdir(parents=True)
    sample = tmp_path / 'input.bin'
    sample.write_bytes(b'benign')
    def fail_clone(resources):
        own(resources, 'container', 'windows')
        raise RuntimeError('boot failed')
    monkeypatch.setattr(managed, 'clone', fail_clone)
    with pytest.raises(RuntimeError, match='boot failed'):
        managed.task(sample)
    journal = json.loads(next(managed.journals.glob('*.json')).read_text())
    assert journal['status'] == 'failed' and journal['cleanup'] == 'completed'
    assert (Path(journal['evidence']) / 'sample.bin').read_bytes() == b'benign'
    assert not (managed.storage / 'work' / journal['run_id']).exists()


def test_guest_marker_command_round_trip_precedes_submission(tmp_path, monkeypatch):
    managed = lab(tmp_path)
    managed.journals.mkdir(parents=True)
    sample = tmp_path / 'probe.exe'
    sample.write_bytes(b'benign')
    monkeypatch.setattr(managed, 'clone', lambda resources: resources.work)
    monkeypatch.setattr(managed, 'wait_agent', lambda *args: None)
    monkeypatch.setattr(managed, 'start_network_simulator', lambda *args: None)
    marker = None
    commands = []
    def agent(guest, path='/', fields=None, optional=False):
        nonlocal marker
        if path == '/retrieve':
            assert fields['filepath'] == r'C:\StealerForge\run-marker.txt'
            return marker
        command = fields['command']
        # The pinned CAPE agent uses POSIX shlex.split even on Windows.
        parts = shlex.split(command)
        assert parts[:2] == ['cmd.exe', '/c']
        assert len(parts) == 3
        assert parts[2].endswith(r'>C:\StealerForge\run-marker.txt')
        assert '\r' not in command and '\n' not in command
        marker = command.split('echo ', 1)[1].split('>', 1)[0]
        commands.append(command)
        return '{}'
    monkeypatch.setattr(managed, 'agent', agent)
    monkeypatch.setattr(RunResources, 'wait', lambda *args: 1)
    with pytest.raises(RuntimeError, match='collection manifest'):
        managed.task(sample)
    assert len(commands) == 1
    launches = [c for c in managed.docker.calls if c[0] == 'run']
    assert any(managed.controller in c for c in launches)
    state = json.loads(next(managed.journals.glob('*.json')).read_text())
    assert state['cleanup'] == 'completed'


def test_missing_storage_parent_fails_without_creating_a_mountpoint(tmp_path):
    managed = lab(tmp_path)
    managed.storage = tmp_path / 'missing-disk' / 'lab'
    with pytest.raises(RuntimeError, match='Mount the data disk'):
        managed.run(cleanup_only=True)
    assert not managed.storage.parent.exists()


def test_recovery_preserves_partial_data(resources, tmp_path):
    own(resources, 'container', 'windows')
    (resources.evidence / 'partial.bin').write_bytes(b'evidence')
    managed = lab(tmp_path, resources.docker)
    managed.storage = resources.storage
    managed.journals = resources.path.parent
    managed.recover()
    state = json.loads(resources.path.read_text())
    assert state['status'] == 'interrupted'
    assert state['cleanup'] == 'completed'
    assert (resources.evidence / 'partial.bin').read_bytes() == b'evidence'


def test_disposable_overlay_uses_readonly_base(tmp_path, monkeypatch):
    managed = lab(tmp_path)
    managed.journals.mkdir(parents=True)
    original = managed.base / 'storage'
    original.mkdir(parents=True)
    (original / 'data.qcow2').write_bytes(b'clean-base')
    (original / 'uefi.vars').write_bytes(b'clean-vars')
    resources = RunResources(managed.docker, managed.journals, managed.storage, tmp_path / 'evidence')
    commands = []
    monkeypatch.setattr(managed, 'helper', lambda r, c, o: commands.append((c, o)))
    clone = managed.clone(resources)
    assert (clone / 'uefi.vars').read_bytes() == b'clean-vars'
    assert not (clone / 'data.qcow2').exists()
    command, options = commands[0]
    assert command[command.index('-b') + 1] == '/base/data.qcow2'
    assert any('dst=/base,readonly' in value for value in options)
    assert (original / 'data.qcow2').read_bytes() == b'clean-base'


def test_guest_analysis_network_has_no_host_sharing(tmp_path):
    managed = lab(tmp_path)
    options = managed.guest_options(tmp_path, 'qmp', tmp_path, 'container:keeper')
    assert options[options.index('--network') + 1] == 'container:keeper'
    assert 'NETWORK=N' in options
    assert 'RAM_CHECK=N' in options and 'RAM_SIZE=4G' in options
    assert options[options.index('--memory') + 1] == '6g'
    assert options[options.index('--memory-swap') + 1] == '6g'
    assert '--privileged' not in options and '--publish' not in options
    assert not any('docker.sock' in value or 'dst=/shared' in value for value in options)
    arguments = next(v for v in options if v.startswith('ARGUMENTS='))
    assert 'hostfwd=tcp:127.0.0.1:8000-:8000' in arguments


def test_host_memory_guard_rejects_insufficient_memory(tmp_path, monkeypatch):
    managed = lab(tmp_path)
    monkeypatch.setattr('core.lab_readiness.inspect_memory',
                        lambda minimum: {'status': 'blocked', 'available_gib': 3})
    with pytest.raises(RuntimeError, match='Insufficient available host memory'):
        managed.require_host_memory()


def test_official_download_resumes_and_checks_cached_integrity(tmp_path, monkeypatch):
    managed = lab(tmp_path)
    managed.base.mkdir(parents=True)
    monkeypatch.setattr('core.managed_lab.WINDOWS_ISO_BYTES', 6)
    calls = []
    class Response(io.BytesIO):
        status = 206
        def geturl(self):
            return WINDOWS_ISO_URL
        def read(self, size):
            if self.broken and self.tell():
                raise OSError('network interruption')
            return super().read(2 if self.broken else size)
    def open_url(request, **kwargs):
        calls.append(request.get_header('Range'))
        offset = 0 if len(calls) == 1 else 2
        response = Response(b'abcdef'[offset:])
        response.broken = offset == 0
        response.headers = {'Content-Range': f'bytes {offset}-5/6', 'Content-Length': str(6 - offset)}
        return response
    monkeypatch.setattr('urllib.request.urlopen', open_url)
    media = managed.download_windows_media()
    assert media.read_bytes() == b'abcdef'
    assert calls == ['bytes=0-', 'bytes=2-']
    assert managed.download_windows_media() == media
    assert len(calls) == 2
    media.write_bytes(b'tamper')
    with pytest.raises(RuntimeError, match='integrity'):
        managed.download_windows_media()


def test_failed_benign_validation_blocks_real_sample(tmp_path, monkeypatch):
    managed = lab(tmp_path)
    managed.base.mkdir(parents=True)
    monkeypatch.setattr(managed, 'ensure_images', lambda: None)
    monkeypatch.setattr(managed, 'require_host_memory', lambda: None)
    monkeypatch.setattr(managed, 'bootstrap', lambda: {'validated': False})
    monkeypatch.setattr(managed, 'helper', lambda *a, **kw: None)
    monkeypatch.setattr('core.managed_lab.shutil.disk_usage', lambda p: type('Space', (), {'free': 100 * 1024**3})())
    real_exists = Path.exists
    monkeypatch.setattr(Path, 'exists', lambda p: True if str(p) == '/dev/kvm' else real_exists(p))
    submissions = []
    def fail_validation(sample, validation=False, **kwargs):
        submissions.append(validation)
        raise RuntimeError('monitor absent')
    monkeypatch.setattr(managed, 'task', fail_validation)
    with pytest.raises(RuntimeError, match='monitor absent'):
        managed.run(tmp_path / 'must-not-submit.exe')
    assert submissions == [True]


def test_qmp_negotiates_and_ignores_async_events(tmp_path):
    path = tmp_path / 'qmp.sock'
    with socket.socket(socket.AF_UNIX) as server:
        try:
            server.bind(str(path))
        except PermissionError:
            pytest.skip('Sandbox disallows binding Unix sockets; run this check in the test container')
        server.listen(1)
        requests = []
        def serve():
            with server.accept()[0] as connection, connection.makefile('rwb', buffering=0) as stream:
                stream.write(b'{"QMP":{"version":{}}}\n')
                for reply in ({}, {'status': 'running'}):
                    request = json.loads(stream.readline())
                    requests.append(request)
                    stream.write(b'{"event":"STOP"}\n')
                    stream.write(json.dumps({'return': reply, 'id': request['id']}).encode() + b'\n')
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        assert execute(path, 'query-status', timeout=2) == {'status': 'running'}
        thread.join(timeout=2)
        assert [r['execute'] for r in requests] == ['qmp_capabilities', 'query-status']


def test_cape_config_waits_for_analysis_before_max_count_shutdown(tmp_path):
    import configparser
    from managed.configure import configure
    defaults = tmp_path / 'cape/conf/default'
    defaults.mkdir(parents=True)
    (defaults / 'cuckoo.conf.default').write_text('[cuckoo]\nignore_signals = yes\n')
    configure(root=tmp_path / 'cape', evidence=tmp_path / 'evidence')
    config = configparser.ConfigParser(interpolation=None)
    config.read(tmp_path / 'cape/custom/conf/cuckoo.conf')
    assert config['cuckoo']['ignore_signals'] == 'no'
    assert config['cuckoo']['max_analysis_count'] == '1'


def test_cape_config_keeps_family_config_extractors_enabled(tmp_path):
    import configparser
    from managed.configure import configure
    defaults = tmp_path / 'cape/conf/default'
    defaults.mkdir(parents=True)
    (defaults / 'processing.conf.default').write_text(
        '[CAPE]\nenabled = yes\n[CAPE_extractors]\nenabled = yes\nparsers = all\n[virustotal]\nenabled = yes\n')
    configure(root=tmp_path / 'cape', evidence=tmp_path / 'evidence')
    config = configparser.ConfigParser(interpolation=None)
    config.read(tmp_path / 'cape/custom/conf/processing.conf')
    assert config['CAPE_extractors']['enabled'] == 'yes'
    assert config['virustotal']['enabled'] == 'no'


def test_adaptive_rerun_targets_only_missing_folders_of_other_profiles_in_short_runs():
    from core.managed_lab import missing_foreign_folders
    def call(stamp, name, result='0xffffffffc000003a', api='NtCreateFile'):
        return {'api': api, 'timestamp': f'2026-11-04 10:00:{stamp:02d},000', 'return': result,
                'arguments': [{'name': 'FileName', 'value': name}]}
    calls = [call(1, 'C:\\Users\\artem\\Documents\\dev\\log.txt'), call(2, 'C:\\Users\\Sarah\\AppData\\x\\y.txt'),
             call(3, 'C:\\Users\\Public\\z\\a.txt'), call(4, 'C:\\Users\\other\\ok.txt', '0x00000000'),
             call(5, 'C:\\Windows\\Temp\\gone\\b.txt'), call(6, 'C:\\Users\\artem\\Documents\\dev\\other.txt')]
    report = {'behavior': {'processes': [{'calls': calls}]}}
    assert missing_foreign_folders(report, 'Sarah') == ['C:\\Users\\artem\\Documents\\dev']
    calls.append({'api': 'NtClose', 'timestamp': '2026-11-04 10:09:00,000'})
    assert missing_foreign_folders(report, 'Sarah') == []
