"""Docker-managed, single-task Windows/CAPE lifecycle with retained evidence.

This module orchestrates containers; it never imports a native malware parser or
executes a submitted input on the host. Only journal-owned resources are removed.
"""
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
GUEST = ROOT / 'managed' / 'guest'
LABEL = 'org.stealerforge.run'
RUN_PATTERN = re.compile(r'^[0-9a-f]{32}$')
GUEST_PATH = re.compile(r'[A-Za-z]:[\\/][^"\'\r\n<>|?*]{1,240}')
# Content length of the official Win10 Enterprise evaluation media.
WINDOWS_ISO_BYTES = 5550497792
WINDOWS_ISO_URL = ('https://software-static.download.prss.microsoft.com/dbazure/'
                   '988969d5-f34g-4e03-ac9d-1f9786c66750/'
                   '19045.2006.220908-0225.22h2_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso')


BUILTIN_PROFILES = {'public', 'default', 'default user', 'all users'}
# Launcher CPU switches. "default" keeps Hyper-V enlightenments, so CPUID leaf 0x40000000 reports "Microsoft Hv"
# like a physical PC with virtualization-based security. Tested on 2026-11-04 with the pinned CAPE monitor:
# "hyperv" (also hides the KVM leaves) made monitored processes hang, and "bare" (no hypervisor bit, no
# enlightenments) made them crash with heap corruption, so neither is the default.
CPU_IDENTITY = {'hyperv': ['-e', 'CPU_FLAGS=kvm=off'],
                'bare': ['-e', 'VM=N', '-e', 'HV=N', '-e', 'CPU_FLAGS=-hypervisor,kvm=off'],
                'default': []}


def missing_foreign_folders(report, user, limit=5):
    """Folders under another user's profile that a short-lived sample failed to open with "path not found".

    Developer builds often log to their author's profile and quit when that fails; recreating the folder in a
    second run lets execution continue. Returns [] unless the sample also ended within two minutes.
    """
    folders, stamps = [], []
    for process in (report.get('behavior') or {}).get('processes') or []:
        for call in process.get('calls') or []:
            if call.get('timestamp'):
                stamps.append(call['timestamp'])
            if call.get('api') not in ('NtCreateFile', 'NtOpenFile', 'CreateDirectoryW', 'CreateFileW'):
                continue
            if not str(call.get('return', '')).lower().endswith('c000003a'):
                continue
            arguments = call.get('arguments') or []
            names = [a.get('value') for a in arguments if isinstance(a, dict) and a.get('name') in ('FileName', 'lpFileName')]
            match = re.match(r'^([A-Za-z]:\\Users\\([^\\]+)\\.+)\\[^\\]+$', str(names[0]) if names else '')
            if not match or match.group(2).lower() in BUILTIN_PROFILES | {user.lower()}:
                continue
            if GUEST_PATH.fullmatch(match.group(1)) and match.group(1) not in folders:
                folders.append(match.group(1))
    if not folders or not stamps:
        return []
    def seconds(value):
        return time.mktime(time.strptime(value.split(',')[0], '%Y-%m-%d %H:%M:%S'))
    return folders[:limit] if seconds(max(stamps)) - seconds(min(stamps)) < 120 else []


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def atomic_json(path, value):
    # Evidence directories are writable by analysis containers. Never follow a
    # pre-created temporary-file symlink when publishing host lifecycle metadata.
    descriptor, name = tempfile.mkstemp(prefix='.managed-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def contained(root, relative):
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()) or candidate == root.resolve():
        raise ValueError('Path escapes its evidence directory')
    return candidate


class Docker:
    def call(self, args, timeout=60, check=True, log=None):
        with tempfile.TemporaryFile() as temporary:
            destination = (os.fdopen(os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'ab')
                           if log else temporary)
            try:
                result = subprocess.run(['docker', *map(str, args)], stdout=destination,
                                        stderr=subprocess.STDOUT, timeout=timeout, check=False)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError('Docker operation timed out; consult the lifecycle journal') from None
            finally:
                if log:
                    destination.close()
            if log:
                output = ''
            else:
                temporary.seek(0)
                output = temporary.read(2097152).decode('utf-8', errors='replace')
            if check and result.returncode:
                detail = f'consult {log}' if log else output[-2000:]
                raise RuntimeError(f'Docker operation failed ({result.returncode}): {detail}')
            return result.returncode, output

    def inspect(self, kind, name):
        code, output = self.call([kind, 'inspect', name], check=False)
        if code:
            if re.search(r'(No such (?:object|container|image|volume)|volume .* not found)', output, re.I):
                return None
            raise RuntimeError(f'Cannot inspect Docker {kind}; recovery cannot assume it is absent: {output[-1000:]}')
        return json.loads(output)[0]


class RunResources:
    def __init__(self, docker, journal_dir, storage, evidence, run_id=None, existing=None):
        self.docker = docker
        self.storage = storage.resolve()
        self.run_id = run_id or uuid4().hex
        if not RUN_PATTERN.fullmatch(self.run_id):
            raise ValueError('Invalid managed run identifier')
        self.path = journal_dir / f'{self.run_id}.json'
        self.evidence = evidence.resolve()
        self.work = self.storage / 'work' / self.run_id
        self.state = existing or {'run_id': self.run_id, 'storage': str(self.storage),
                                 'evidence': str(self.evidence), 'resources': [], 'status': 'preparing',
                                 'cleanup_errors': [], 'events': []}
        if self.state['run_id'] != self.run_id or self.state['storage'] != str(self.storage):
            raise ValueError('Journal identity mismatch')
        if not existing:
            self.evidence.mkdir(parents=True, exist_ok=False)
            self.work.mkdir(parents=True)
            atomic_json(self.work / '.owner.json', {'run_id': self.run_id})
        self.save()

    def save(self):
        atomic_json(self.path, self.state)

    def event(self, phase, **values):
        self.state['events'].append({'phase': phase, 'time': time.time(), **values})
        self.save()
        print(f'Managed lab: {phase}', flush=True)

    def reserve(self, kind, suffix):
        name = f'sf-{self.run_id}-{suffix}'
        self.state['resources'].append({'kind': kind, 'name': name})
        self.save()  # Journal before issuing mutations, including ambiguous timeouts.
        return name

    def volume(self, suffix):
        name = self.reserve('volume', suffix)
        self.docker.call(['volume', 'create', '--label', f'{LABEL}={self.run_id}', name])
        return name

    def start(self, suffix, options, image, command=()):
        name = self.reserve('container', suffix)
        self.docker.call(['run', '-d', '--name', name, '--label', f'{LABEL}={self.run_id}',
                          '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3',
                          *options, image, *command])
        return name

    def wait(self, name, timeout, reserve_gib=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            instance = self.docker.inspect('container', name)
            if not instance:
                raise RuntimeError('Managed container disappeared')
            if not instance['State']['Running']:
                return instance['State']['ExitCode']
            if shutil.disk_usage(self.storage).free < reserve_gib * 1024**3:
                raise RuntimeError('Lab disk reserve exhausted; stopping the run and preserving collected evidence')
            time.sleep(2)
        raise RuntimeError(f'Managed stage exceeded its {timeout}-second deadline')

    def cleanup(self):
        errors = []
        # Containers are created in dependency order. Remove children before namespace holder.
        for resource in reversed(self.state['resources']):
            try:
                if (resource['kind'] not in ('container', 'volume')
                        or not resource['name'].startswith(f'sf-{self.run_id}-')):
                    raise RuntimeError('Invalid resource identity in recovery journal')
                item = self.docker.inspect(resource['kind'], resource['name'])
                if item is None:
                    continue
                labels = item.get('Config', {}).get('Labels', {}) if resource['kind'] == 'container' else item.get('Labels', {})
                if (labels or {}).get(LABEL) != self.run_id:
                    raise RuntimeError('Ownership label does not match; resource retained')
                if resource['kind'] == 'container':
                    self.docker.call(['stop', '-t', '10', resource['name']], timeout=30, check=False)
                    self.docker.call(['logs', '--timestamps', resource['name']], check=False,
                                     log=self.evidence / f'{resource["name"]}.log')
                    self.docker.call(['rm', '-f', resource['name']])
                else:
                    self.docker.call(['volume', 'rm', resource['name']])
            except Exception as exc:
                errors.append({'resource': resource['name'], 'error': str(exc)})
        # Never discard a VM's disk while any owned resource may still be using it.
        if not errors and self.work.exists():
            try:
                if self.work.is_symlink() or self.work.parent.resolve() != (self.storage / 'work').resolve():
                    raise RuntimeError('Invalid disposable workspace')
                if json.loads((self.work / '.owner.json').read_text()) != {'run_id': self.run_id}:
                    raise RuntimeError('Disposable workspace ownership marker mismatch')
                shutil.rmtree(self.work)
            except Exception as exc:
                errors.append({'resource': str(self.work), 'error': str(exc)})
        self.state['cleanup_errors'] = errors
        self.state['cleanup'] = 'failed' if errors else 'completed'
        self.save()
        atomic_json(self.evidence / 'managed_run.json', self.state)
        return not errors


def bind(source, target, readonly=False):
    if ',' in str(source):
        raise ValueError('Docker bind paths cannot contain commas')
    return ['--mount', f'type=bind,src={Path(source).resolve()},dst={target}' + (',readonly' if readonly else '')]


def image_fingerprint(paths):
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


class ManagedLab:
    def __init__(self, settings, docker=None):
        self.cfg = settings
        self.docker = docker or Docker()
        self.storage = Path(settings['storage_directory']).resolve()
        self.state_root = Path(settings['state_directory']).resolve()
        if self.storage == Path('/') or self.state_root == Path('/'):
            raise ValueError('Managed directories must be dedicated folders')
        self.lock = json.loads((ROOT / 'managed/assets.lock.json').read_text())
        self.windows = self.lock['windows_image']
        source = [p for p in (ROOT / 'managed').rglob('*') if p.is_file() and '__pycache__' not in p.parts]
        self.persona_settings = {key: settings[f'persona_{key}'] for key in ('username', 'hostname', 'organization', 'timezone')
                                 if settings.get(f'persona_{key}')}
        # Everything that ends up inside the clean base: a change means a new base and a fresh install.
        self.recipe = image_fingerprint([ROOT / 'managed/assets.lock.json', ROOT / 'managed/persona.py',
                                         *(p for p in GUEST.rglob('*') if p.is_file() and '__pycache__' not in p.parts)])
        self.recipe = hashlib.sha256((self.recipe + WINDOWS_ISO_URL + json.dumps(self.persona_settings, sort_keys=True))
                                     .encode()).hexdigest()[:16]
        self.controller = 'stealerforge-cape:' + image_fingerprint(source)
        analysis_source = list((ROOT / 'core').glob('*.py')) + [ROOT / p for p in (
            'main.py', 'Dockerfile', '.dockerignore', 'config.yaml', 'requirements.lock', 'requirements-dev.lock', 'requirements-engines.lock',
            'container/config.yaml', 'container/assets.lock.json', 'scripts/fetch_assets.py')]
        self.analyzer = 'stealerforge-analysis:managed-' + image_fingerprint(analysis_source)
        self.diskedit = 'stealerforge-diskedit:' + image_fingerprint(list((ROOT / 'managed/diskedit').iterdir()))
        self.base = self.storage / 'bases' / self.recipe
        self.journals = self.state_root / 'runs'

    def ensure_images(self):
        if self.docker.inspect('image', self.windows) is None:
            print('Managed lab: downloading pinned VM launcher', flush=True)
            self.docker.call(['pull', self.windows], timeout=1800, log=self.state_root / 'windows-build.log')
        for image, context, extra in ((self.controller, ROOT / 'managed', []),
                                      (self.analyzer, ROOT, ['--target', 'runtime']),
                                      (self.diskedit, ROOT / 'managed/diskedit', [])):
            if self.docker.inspect('image', image) is None:
                print(f'Managed lab: building {image}', flush=True)
                self.docker.call(['build', '-t', image, *extra, str(context)], timeout=3600,
                                 log=self.state_root / f'{image.split(":")[0].rsplit("-", 1)[-1]}-build.log')

    def helper(self, resources, command, options=(), image=None, timeout=120):
        name = resources.start('helper-' + secrets.token_hex(3),
                               ['--network', 'none', '--entrypoint', command[0], *options],
                               image or self.windows, command[1:])
        code = resources.wait(name, timeout)
        if code:
            raise RuntimeError(f'Managed helper failed with exit code {code}; its log will be retained')
        return name

    def hardware(self):
        """Per-base hardware identity (SMBIOS, ACPI OEM IDs, disk strings, MAC) matching the persona's machine."""
        from core.hardware import generate
        path = self.base / 'hardware.json'
        if not path.is_file():
            identity = (self.persona() if (self.base / 'persona.json').is_file() else {}).get('identity', {})
            self.base.mkdir(parents=True, exist_ok=True)
            atomic_json(path, generate(identity))
        return json.loads(path.read_text())

    def guest_options(self, storage, qmp_volume, evidence, network):
        from core.hardware import readconfig
        hardware = self.hardware()
        (Path(storage) / 'hardware.cfg').write_text(readconfig(hardware))
        # NETWORK=N disables the launcher's TAP, SMB and port auto-forwarding logic.
        # Explicit slirp traffic shares a namespace with loopback only during analysis.
        # Hardware identity: real-vendor SMBIOS/ACPI/disk/MAC strings instead of QEMU's; CPU identity per
        # CPU_IDENTITY (VM/HV/CPU_FLAGS are the launcher's own switches).
        arguments = ('-netdev user,id=sfnet,hostfwd=tcp:127.0.0.1:8000-:8000 '
                     f'-device e1000,netdev=sfnet,mac={hardware["mac"]} '
                     '-qmp unix:/qmp/control.sock,server=on,wait=off '
                     '-object filter-dump,id=sfcapture,netdev=sfnet,file=/evidence/guest.pcap '
                     '-readconfig /storage/hardware.cfg '
                     f'-machine x-oem-id={hardware["acpi_oem_id"]},x-oem-table-id={hardware["acpi_table_id"]}')
        return ['--network', network, '--device', '/dev/kvm', '--security-opt', 'no-new-privileges:true',
                '--pids-limit', '256', '--memory', '6g', '--memory-swap', '6g', '--cpus', str(self.cfg['guest_cpus']),
                '-e', 'NETWORK=N', '-e', 'DISK_FMT=qcow2', '-e', 'DISK_SIZE=64G',
                '-e', 'RAM_SIZE=4G', '-e', 'RAM_CHECK=N', '-e', f'CPU_CORES={self.cfg["guest_cpus"]}', '-e', 'VERSION=' + WINDOWS_ISO_URL,
                *CPU_IDENTITY[self.cfg['cpu_identity']],
                '-e', 'UUID=' + hardware['uuid'], '-e', 'BIOS_SERIAL=' + hardware['serial'],
                '-e', f'ARGUMENTS={arguments}', '-v', f'{qmp_volume}:/qmp',
                *bind(storage, '/storage'), *bind(evidence, '/evidence')]

    def agent(self, guest, path='/', fields=None, optional=False):
        # Just after logon on HDD storage, starting cmd.exe for /execute can exceed several seconds.
        args = ['exec', guest, 'curl', '--silent', '--show-error', '--fail', '--max-time', '60']
        if fields:
            for key, value in fields.items():
                args += ['--data-urlencode', f'{key}={value}']
        code, output = self.docker.call([*args, 'http://127.0.0.1:8000' + path], timeout=75, check=False)
        if code and not optional:
            raise RuntimeError(f'CAPE guest agent request failed ({code}): {output.strip()[-500:]}')
        return None if code else output

    def wait_agent(self, resources, guest, timeout):
        started = time.monotonic()
        deadline = started + timeout
        next_progress = started + 60
        while time.monotonic() < deadline:
            item = self.docker.inspect('container', guest)
            if not item or not item['State']['Running']:
                raise RuntimeError('Windows stopped before the CAPE agent became ready')
            if self.agent(guest, optional=True) is not None:
                recipe = self.agent(guest, '/retrieve', {'filepath': r'C:\StealerForge\recipe.txt'}, optional=True)
                if recipe is not None and recipe.strip() == self.recipe:
                    resources.event('guest_agent_ready', elapsed_seconds=int(time.monotonic() - started))
                    return
            if shutil.disk_usage(self.storage).free < self.cfg['reserve_free_gib'] * 1024**3:
                raise RuntimeError('Lab disk reserve exhausted during Windows startup')
            if time.monotonic() >= next_progress:
                resources.event('waiting_for_guest_agent', elapsed_seconds=int(time.monotonic() - started))
                next_progress = time.monotonic() + 60
            time.sleep(5)
        raise RuntimeError('Windows/CAPE agent provisioning timed out; inspect the retained launcher log')

    def fetch_asset(self, spec, destination):
        """Download one guest asset through a cache. Pinned hashes must match; unpinned vendor "latest" builds
        are recorded in the base manifest and their code signature is verified inside the guest."""
        cache = self.storage / 'cache' / 'assets'
        cache.mkdir(parents=True, exist_ok=True)
        cached = cache / hashlib.sha256(spec['url'].encode()).hexdigest()[:24]
        if not cached.is_file() or (spec.get('sha256') and sha256(cached) != spec['sha256']):
            partial = cached.with_suffix('.part')
            request = urllib.request.Request(spec['url'], headers={'User-Agent': 'StealerForge/managed-lab'})
            with urllib.request.urlopen(request, timeout=60) as response, partial.open('wb') as stream:
                total = 0
                while block := response.read(1048576):
                    total += len(block)
                    if total > spec['max_bytes']:
                        raise RuntimeError(f'{spec["url"]} exceeded its download limit')
                    stream.write(block)
            if spec.get('sha256') and sha256(partial) != spec['sha256']:
                partial.unlink()
                raise RuntimeError(f'Checksum mismatch for {spec["url"]}')
            partial.replace(cached)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(cached, destination)
        return {'url': spec['url'], 'sha256': sha256(destination), 'size_bytes': destination.stat().st_size,
                'pinned': bool(spec.get('sha256')), 'signer': spec.get('signer')}

    def persona(self):
        """The base's victim persona and canaries; generated once per base, never committed or exported."""
        from managed.persona import generate
        path = self.base / 'persona.json'
        if not path.is_file():
            self.base.mkdir(parents=True, exist_ok=True)
            atomic_json(path, generate(self.persona_settings))
            path.chmod(0o600)
        return json.loads(path.read_text())

    def bootstrap(self):
        manifest = self.base / 'base.json'
        if manifest.is_file():
            data = json.loads(manifest.read_text())
            if data.get('recipe') == self.recipe and data.get('sealed') and (self.base / 'storage/data.qcow2').is_file():
                return data
            raise RuntimeError('Existing base manifest is invalid; it will not be silently overwritten')
        self.base.mkdir(parents=True, exist_ok=True)
        storage = self.base / 'storage'
        if storage.is_dir() and any(storage.iterdir()):
            # An unsealed disk from an interrupted attempt would boot half-provisioned instead of reinstalling.
            shutil.rmtree(storage)
        storage.mkdir(exist_ok=True)
        seed = self.base / 'oem'
        seed.mkdir(exist_ok=True)
        resources = RunResources(self.docker, self.journals, self.storage,
                                 self.storage / 'provisioning' / uuid4().hex)
        try:
            resources.event('provisioning_clean_windows')
            self.helper(resources, ['cp', '/opt/CAPEv2/agent/agent.py', '/seed/agent.py'],
                        bind(seed, '/seed'), image=self.controller)
            resources.event('downloading_guest_assets')
            assets = {'python': self.fetch_asset({'url': self.lock['python_url'], 'sha256': self.lock['python_sha256'],
                                                  'max_bytes': 67108864}, seed / 'python-installer.exe')}
            for name, spec in self.lock['guest_assets'].items():
                assets[name] = self.fetch_asset(spec, seed / spec['file'])
            for path in GUEST.iterdir():
                if path.is_file():
                    shutil.copyfile(path, seed / path.name)
            persona = self.persona()
            shutil.copyfile(self.base / 'persona.json', seed / 'persona.json')
            ca = self.base / 'netsim-ca'
            if not (ca / 'ca.crt').is_file():
                ca.mkdir(exist_ok=True)
                self.helper(resources, ['python', '/opt/stealerforge-managed/netsim.py', 'make-ca', '/ca',
                                        '--organization', persona['identity']['organization']],
                            bind(ca, '/ca'), image=self.controller)
            shutil.copyfile(ca / 'ca.crt', seed / 'netsim-ca.crt')
            (seed / 'recipe.txt').write_text(self.recipe)
            resources.event('acquiring_official_windows_media')
            media = self.download_windows_media()
            qmp = resources.volume('qmp')
            identity = persona['identity']
            options = [*self.guest_options(storage, qmp, resources.evidence, 'bridge'),
                       *bind(media, '/boot.iso', True)]
            guest = resources.start('windows', [*options, *bind(seed, '/oem', True),
                                                '-e', 'PASSWORD=' + secrets.token_urlsafe(24),
                                                '-e', 'USERNAME=' + identity['username'], '-e', 'HOST=' + identity['hostname'],
                                                '-e', 'WIDTH=1920', '-e', 'HEIGHT=1080'], self.windows)
            # recipe.txt is copied last by install.bat, so a ready agent also means provisioning finished.
            self.wait_agent(resources, guest, self.cfg['provision_timeout_seconds'])
            report = self.agent(guest, '/retrieve', {'filepath': r'C:\StealerForge\provision.json'})
            (self.base / 'provision.json').write_text(report)
            log = self.agent(guest, '/retrieve', {'filepath': r'C:\StealerForge\provision.log'}, optional=True)
            if log is not None:
                (self.base / 'provision.log').write_text(log)
            provision = json.loads(report)
            if not provision.get('ok'):
                raise RuntimeError(f'Guest provisioning failed in {provision.get("failed")}; see {self.base / "provision.json"}')
            resources.event('guest_provisioned', steps=sorted(provision['steps']))
            # C:\OEM holds the installers and persona file: a sandbox tell, and not needed after provisioning.
            self.agent(guest, '/execute', {'command': 'C:/StealerForge/Python/python.exe -c '
                                                      '"import shutil; shutil.rmtree(\'C:/OEM\', ignore_errors=True)"'})
            self.agent(guest, '/execute', {'command': 'cmd.exe /c shutdown /s /t 3', 'async': 'yes'})
            if resources.wait(guest, 180) != 0:
                raise RuntimeError('Windows did not shut down cleanly; base will not be sealed')
            resources.event('disabling_defender_offline')
            self.helper(resources, ['sh', '/opt/diskedit/disable-defender.sh', '/storage/data.qcow2'],
                        [*bind(storage, '/storage'), '--device', '/dev/kvm'], image=self.diskedit, timeout=900)
            self.helper(resources, ['qemu-img', 'check', '/storage/data.qcow2'], bind(storage, '/storage'))
            data = {'recipe': self.recipe, 'sealed': True, 'validated': False,
                    'windows_image': self.windows, 'cape_commit': self.lock['cape_commit'],
                    'disk_sha256': sha256(storage / 'data.qcow2'), 'created_at': time.time(),
                    'identity': identity, 'guest_assets': assets,
                    'provision': {k: v.get('detail') for k, v in provision['steps'].items()}}
            atomic_json(manifest, data)
            resources.state['status'] = 'sealed'
            return data
        except BaseException as exc:
            resources.state.update(status='failed', error=f'{type(exc).__name__}: {exc}')
            raise
        finally:
            if not resources.cleanup():
                raise RuntimeError('Provisioning cleanup failed; inspect the lifecycle journal')

    def download_windows_media(self):
        """Download only Microsoft's fixed URL, resuming interrupted transfers."""
        media = self.base / 'installation.iso'
        receipt = self.base / 'installation.json'
        if media.is_file():
            saved = json.loads(receipt.read_text())
            if (saved.get('source') != WINDOWS_ISO_URL or media.stat().st_size != WINDOWS_ISO_BYTES
                    or sha256(media) != saved['sha256']):
                raise RuntimeError('Cached Windows installation media integrity check failed')
            return media
        for other in sorted((self.storage / 'bases').glob('*/installation.json')):
            # Another base already holds the same verified media: reuse it instead of downloading 5.5 GB again.
            saved = json.loads(other.read_text())
            source = other.parent / 'installation.iso'
            if (other.parent != self.base and saved.get('source') == WINDOWS_ISO_URL and source.is_file()
                    and source.stat().st_size == WINDOWS_ISO_BYTES and sha256(source) == saved.get('sha256')):
                print(f'Managed lab: reusing verified Windows media from {other.parent.name}', flush=True)
                partial = self.base / 'installation.part'
                shutil.copyfile(source, partial)
                if sha256(partial) != saved['sha256']:
                    partial.unlink()
                    break
                atomic_json(receipt, saved)
                partial.replace(media)
                return media
        partial = self.base / 'installation.part'
        deadline = time.monotonic() + self.cfg['provision_timeout_seconds']
        next_progress = 0
        for attempt in range(3):
            offset = partial.stat().st_size if partial.exists() else 0
            if offset > WINDOWS_ISO_BYTES:
                raise RuntimeError('Partial Windows download exceeds expected size')
            if offset == WINDOWS_ISO_BYTES:
                break
            request = urllib.request.Request(WINDOWS_ISO_URL, headers={
                'Range': f'bytes={offset}-', 'User-Agent': 'StealerForge/managed-lab', 'Accept-Encoding': 'identity'})
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    if response.geturl() != WINDOWS_ISO_URL:
                        raise RuntimeError('Windows download redirected away from the pinned Microsoft URL')
                    if response.status == 206:
                        expected = f'bytes {offset}-{WINDOWS_ISO_BYTES - 1}/{WINDOWS_ISO_BYTES}'
                        if response.headers.get('Content-Range') != expected:
                            raise RuntimeError('Windows download returned an unexpected byte range')
                    elif response.status == 200:
                        offset = 0  # Server declined Range; restart instead of appending duplicate data.
                    else:
                        raise RuntimeError('Unexpected Windows download response')
                    if int(response.headers.get('Content-Length', -1)) != WINDOWS_ISO_BYTES - offset:
                        raise RuntimeError('Windows media size differs from the pinned release')
                    with partial.open('ab' if offset else 'wb') as stream:
                        while block := response.read(1048576):
                            offset += len(block)
                            if offset > WINDOWS_ISO_BYTES:
                                raise RuntimeError('Windows download exceeded the expected size')
                            stream.write(block)
                            if time.monotonic() > deadline:
                                raise RuntimeError('Windows media download deadline exceeded; partial file retained')
                            if time.monotonic() >= next_progress:
                                print(f'Managed lab: Windows download {offset * 100 // WINDOWS_ISO_BYTES}% (resume supported)', flush=True)
                                next_progress = time.monotonic() + 60
                    if offset != WINDOWS_ISO_BYTES:
                        raise OSError('Windows download ended before the expected size')
                break
            except (OSError, urllib.error.URLError, http.client.IncompleteRead) as exc:
                if attempt == 2 or time.monotonic() >= deadline:
                    raise RuntimeError('Official Windows download failed; partial data retained for the next run') from exc
                print('Managed lab: retrying official Windows download from retained offset', flush=True)
        atomic_json(receipt, {'source': WINDOWS_ISO_URL, 'sha256': sha256(partial), 'size_bytes': WINDOWS_ISO_BYTES})
        partial.replace(media)
        return media

    def clone(self, resources):
        original = self.base / 'storage'
        clone = resources.work / 'windows'
        clone.mkdir()
        for path in original.rglob('*'):
            relative = path.relative_to(original)
            target = clone / relative
            if path.is_symlink():
                raise RuntimeError('Unexpected symlink in clean base storage')
            if path.is_dir():
                target.mkdir(exist_ok=True)
            elif path.is_file() and relative.as_posix() != 'data.qcow2':
                if path.stat().st_size > 33554432:
                    target.symlink_to('/base/' + relative.as_posix())
                else:
                    shutil.copyfile(path, target)
        self.helper(resources, ['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2',
                               '-b', '/base/data.qcow2', '/storage/data.qcow2'],
                    [*bind(original, '/base', True), *bind(clone, '/storage')])
        return clone

    def start_network_simulator(self, resources, keeper, evidence):
        """Fake DNS/TLS/HTTP/SMTP/FTP inside the sealed namespace, then routing that sends all traffic to it."""
        ca = self.base / 'netsim-ca'
        if not (ca / 'ca.key').is_file():
            raise RuntimeError('This base has no network simulator CA; rebuild the base')
        out = evidence / 'netsim'
        out.mkdir()
        resources.start('netsim', ['--network', 'container:' + keeper, '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true', '--memory', '512m', '--pids-limit', '256',
            '--tmpfs', '/tmp:size=64m,mode=1777', '--entrypoint', 'python', *bind(ca, '/ca', True), *bind(out, '/netsim')],
            self.controller, ['/opt/stealerforge-managed/netsim.py', 'serve', '--ca', '/ca', '--out', '/netsim',
                              '--public-ip', self.cfg['public_ip']])
        deadline = time.monotonic() + 60
        while not (out / 'events.jsonl').is_file():
            if time.monotonic() > deadline:
                raise RuntimeError('Network simulator did not start')
            time.sleep(1)
        setup = resources.start('netsetup', ['--network', 'container:' + keeper, '--cap-drop', 'ALL',
            '--cap-add', 'NET_ADMIN', '--user', '0', '--security-opt', 'no-new-privileges:true',
            '--entrypoint', 'sh'], self.controller, ['/opt/stealerforge-managed/netsetup.sh'])
        if resources.wait(setup, 60):
            raise RuntimeError('Network simulator routing setup failed; see its container log')
        resources.event('network_simulator_ready')

    def check_guest_state(self, guest):
        """A validated base must run Sysmon and must not run Microsoft Defender (it would remove samples)."""
        def service(name):
            reply = json.loads(self.agent(guest, '/execute', {'command': f'sc.exe query {name}'}))
            return reply.get('stdout') or ''
        if 'RUNNING' in service('WinDefend'):
            raise RuntimeError('Microsoft Defender is running in the analysis guest')
        if 'RUNNING' not in service(self.persona()['sysmon']['service']):
            raise RuntimeError('Sysmon is not running in the analysis guest')

    def task(self, sample, validation=False, output=None, guest_paths=()):
        for path in guest_paths:
            if not GUEST_PATH.fullmatch(path):
                raise ValueError(f'Guest path must be an absolute Windows path without quotes: {path!r}')
        run_id = uuid4().hex
        evidence = (Path(output) if output else self.storage / ('validation' if validation else 'evidence')) / run_id
        resources = RunResources(self.docker, self.journals, self.storage, evidence, run_id)
        try:
            shutil.copyfile(sample, resources.work / 'sample.bin')
            sample = resources.work / 'sample.bin'
            shutil.copyfile(sample, evidence / 'sample.bin')
            resources.event('creating_disposable_guest', validation=validation, sample_sha256=sha256(sample))
            clone = self.clone(resources)
            qmp = resources.volume('qmp')
            keeper = resources.start('network', ['--network', 'none', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges:true', '--memory', '128m', '--pids-limit', '16',
                '--entrypoint', '/opt/core/bin/python'], self.analyzer, ['-c', 'import time; time.sleep(86400)'])
            self.start_network_simulator(resources, keeper, evidence)
            guest = resources.start('windows', [*self.guest_options(clone, qmp, evidence, 'container:' + keeper),
                *bind(self.base / 'storage', '/base', True)], self.windows)
            self.wait_agent(resources, guest, self.cfg['boot_timeout_seconds'])
            if self.agent(guest, '/retrieve', {'filepath': r'C:\StealerForge\run-marker.txt'}, optional=True) is not None:
                raise RuntimeError('Guest contains a previous run marker; refusing sample submission')
            # Observe cleanliness before adding the marker; it must not enter the base image.
            self.agent(guest, '/execute', {'command': rf'cmd.exe /c "echo {run_id}>C:\StealerForge\run-marker.txt"'})
            marker = self.agent(guest, '/retrieve', {'filepath': r'C:\StealerForge\run-marker.txt'})
            if marker.strip() != run_id:
                raise RuntimeError('Guest write/read readiness probe failed')
            if validation:
                self.check_guest_state(guest)
            for path in guest_paths:
                # Analyst-requested environment, e.g. a folder a sample insists on before it continues.
                self.agent(guest, '/execute', {'command': 'C:/StealerForge/Python/python.exe -c '
                                                          f'"import os; os.makedirs({path.replace(chr(92), "/")!r}.replace(chr(47), chr(92)), exist_ok=True)"'})
            if guest_paths:
                resources.event('guest_paths_created', paths=list(guest_paths))
            self.docker.call(['exec', guest, 'chmod', '666', '/qmp/control.sock'])
            resources.event('running_cape', namespace='simulated_internet', input_retained=True)
            controller = resources.start('controller', ['--network', 'container:' + keeper,
                '--security-opt', 'no-new-privileges:true', '--cap-drop', 'ALL', '--memory', '4g',
                '--memory-swap', '4g', '--cpus', '2', '--pids-limit', '256',
                '-v', f'{qmp}:/qmp', *bind(evidence, '/evidence'), *bind(sample, '/input/sample.bin', True)],
                self.controller, ['--timeout', str(30 if validation else self.cfg['analysis_seconds']),
                                  '--deadline', str(self.cfg['task_timeout_seconds']),
                                  '--options', self.cfg.get('monitor_options', 'procmemdump=1,import_reconstruction=1')])
            code = resources.wait(controller, self.cfg['task_timeout_seconds'] * 2 + 120,
                                  self.cfg['reserve_free_gib'])
            status_file = evidence / 'controller_status.json'
            if not status_file.is_file() or status_file.stat().st_size > 16777216:
                raise RuntimeError('Controller produced no bounded collection manifest')
            result = json.loads(status_file.read_text())
            if code or result.get('status') != 'completed':
                raise RuntimeError('CAPE collection failed; inspect controller_status.json and logs')
            report = contained(evidence, result['report'])
            if not report.is_file() or report.stat().st_size > 268435456:
                raise RuntimeError('CAPE report exceeds the processing limit')
            if sha256(report) != result['report_sha256'] or result['input_sha256'] != sha256(sample):
                raise RuntimeError('CAPE evidence identity mismatch')
            from core.canaries import scan_netsim
            from managed.persona import canary_strings
            hits = scan_netsim(evidence / 'netsim', canary_strings(self.persona()))
            atomic_json(evidence / 'canary_hits.json', hits)
            resources.state['canary_hits'] = len(hits['hits'])
            if validation:
                data = json.loads(report.read_text())
                calls = [call for process in data.get('behavior', {}).get('processes', []) for call in process.get('calls', [])]
                if not calls or 'canary.txt' not in json.dumps(calls).lower():
                    raise RuntimeError('Benign probe did not yield the expected monitored file operation')
                events = [json.loads(line) for line in (evidence / 'netsim/events.jsonl').read_text().splitlines()]
                if not any(e['kind'] == 'http' and e.get('sni') == 'validation.stealerforge-lab.net'
                           and e.get('target') == '/probe' for e in events):
                    raise RuntimeError('Benign probe HTTPS request did not reach the network simulator through TLS interception')
                from core.lab_evidence import sysmon_events
                if not any(e.get('EventID') == 1 for e in sysmon_events(evidence) or []):
                    raise RuntimeError('Sysmon telemetry was not collected from the guest')
                resources.state['status'] = 'validated'
            else:
                resources.event('collecting_and_enriching_evidence')
                self.enrich(resources, sample, report, result['artifacts'])
                resources.state['status'] = 'completed'
            return evidence
        except BaseException as exc:
            resources.state.update(status='interrupted' if isinstance(exc, KeyboardInterrupt) else 'failed',
                                   error=f'{type(exc).__name__}: {exc}')
            raise
        finally:
            if not resources.cleanup():
                raise RuntimeError('Managed cleanup failed; evidence and recovery journal retained')

    def enrich(self, resources, sample, report, artifacts, evidence=None):
        evidence = evidence or resources.evidence
        output = evidence / 'analysis'
        output.mkdir(exist_ok=True)  # each analysis gets its own timestamped subfolder
        command = ['/app/main.py', '-c', '/app/container/config.yaml', '-f', '/input/sample.bin',
                   '--cape-report', '/evidence/' + str(report.relative_to(evidence)),
                   '--local-engines', '--offline-llm', '--retain-artifacts', '--lab-evidence', '/evidence',
                   '--output', '/output']
        accepted = 0
        for artifact in artifacts:
            path = contained(evidence, artifact['path'])
            if path.is_symlink() or not path.is_file() or sha256(path) != artifact['sha256']:
                raise RuntimeError('Collected artifact verification failed')
            if accepted < self.cfg['max_enrichment_artifacts'] and artifact['size_bytes'] <= 134217728:
                command += ['--artifact', '/evidence/' + artifact['path']]
                accepted += 1
        resources.state['enrichment_selection'] = {'selected': accepted, 'retained_raw': len(artifacts)}
        worker = resources.start('analysis', ['--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true', '--pids-limit', '128', '--memory', '4g',
            '--memory-swap', '4g', '--cpus', '2', '--tmpfs', '/tmp:size=1g,mode=1777,noexec,nosuid,nodev',
            '--tmpfs', '/home/analyst:size=128m,uid=1000,gid=1000,mode=0700',
            '--entrypoint', '/opt/core/bin/python', *bind(sample, '/input/sample.bin', True),
            *bind(evidence, '/evidence', True), *bind(output, '/output')], self.analyzer, command)
        code = resources.wait(worker, self.cfg['enrichment_timeout_seconds'], self.cfg['reserve_free_gib'])
        if code not in (0, 2):
            raise RuntimeError('Post-analysis enrichment failed; raw CAPE evidence is retained')
        resources.state['analysis_exit_code'] = code

    def reanalyze(self, evidence):
        """Re-run only the offline enrichment and report for an existing evidence folder (no guest is booted)."""
        evidence = Path(evidence).resolve()
        status = json.loads((evidence / 'controller_status.json').read_text())
        if status.get('status') != 'completed':
            raise RuntimeError('Only completed managed runs can be re-analysed')
        report = contained(evidence, status['report'])
        resources = RunResources(self.docker, self.journals, self.storage, evidence / 'reanalysis' / uuid4().hex)
        try:
            self.enrich(resources, contained(evidence, 'sample.bin'), report, status['artifacts'], evidence=evidence)
            resources.state['status'] = 'completed'
        except BaseException as exc:
            resources.state.update(status='failed', error=f'{type(exc).__name__}: {exc}')
            raise
        finally:
            if not resources.cleanup():
                raise RuntimeError('Managed cleanup failed; inspect the lifecycle journal')
        return evidence

    def run(self, sample=None, prepare_only=False, cleanup_only=False, output=None, guest_paths=(), reanalyze=None):
        previous = signal.getsignal(signal.SIGTERM)
        def terminate(signum, frame):
            raise KeyboardInterrupt('Termination requested; cleaning up owned resources')
        signal.signal(signal.SIGTERM, terminate)
        try:
            return self._run(sample, prepare_only, cleanup_only, output, guest_paths, reanalyze)
        finally:
            signal.signal(signal.SIGTERM, previous)

    def require_host_memory(self):
        # The launcher subtracts its entire cgroup memory.current, including the
        # downloaded ISO's reclaimable page cache. Check host MemAvailable here
        # and retain Docker's hard 6-GiB limit instead of shrinking guest RAM.
        from core.lab_readiness import inspect_memory
        memory = inspect_memory(self.cfg['min_available_gib'])
        if memory['status'] != 'passed':
            raise RuntimeError(f'Insufficient available host memory: {memory["available_gib"]} GiB; '
                               f'{self.cfg["min_available_gib"]} GiB required')

    def _run(self, sample, prepare_only, cleanup_only, output, guest_paths=(), reanalyze=None):
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.journals.mkdir(exist_ok=True)
        with (self.state_root / 'managed.lock').open('a') as lockfile:
            try:
                fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('Another managed lab operation is active') from None
            if not self.storage.parent.is_dir():
                raise RuntimeError(f'Lab storage parent is unavailable: {self.storage.parent}. Mount the data disk before running.')
            self.storage.mkdir(exist_ok=True)
            self.recover()
            if cleanup_only:
                print('Managed cleanup completed; evidence retained', flush=True)
                return 0
            if shutil.disk_usage(self.storage).free < self.cfg['min_free_gib'] * 1024**3:
                raise RuntimeError('Insufficient free lab storage')
            if not Path('/dev/kvm').exists():
                raise RuntimeError('KVM is unavailable to this process; run on the Linux host with /dev/kvm enabled')
            if reanalyze:
                self.ensure_images()
                evidence = self.reanalyze(reanalyze)
                print(f'Managed evidence re-analysed: {evidence / "analysis"}', flush=True)
                return 0
            self.require_host_memory()
            self.ensure_images()
            manifest = self.bootstrap()
            # Revalidate when the controller image or the guest's runtime hardware settings change.
            runtime = {'cpu_identity': self.cfg['cpu_identity'], 'guest_cpus': self.cfg['guest_cpus']}
            if (not manifest.get('validated') or manifest.get('validation_controller') != self.controller
                    or manifest.get('validation_runtime') != runtime):
                # Extract the deterministic benign fixture from the built controller image.
                seed = self.base / 'validation-input'
                seed.mkdir(exist_ok=True)
                resources = RunResources(self.docker, self.journals, self.storage,
                                         self.storage / 'provisioning' / uuid4().hex)
                try:
                    self.helper(resources, ['cp', '/opt/stealerforge-managed/probe.exe', '/seed/probe.exe'],
                                bind(seed, '/seed'), image=self.controller)
                finally:
                    if not resources.cleanup():
                        raise RuntimeError('Fixture extraction cleanup failed')
                validation = self.task(seed / 'probe.exe', validation=True)
                manifest.update(validated=True, validation_evidence=str(validation), validated_at=time.time(),
                                validation_controller=self.controller, validation_runtime=runtime)
                atomic_json(self.base / 'base.json', manifest)
            if prepare_only:
                print(f'Managed base validated: {self.base}', flush=True)
                return 0
            evidence = self.task(Path(sample).resolve(), output=output, guest_paths=guest_paths)
            print(f'Managed evidence retained: {evidence}', flush=True)
            if self.cfg['adaptive_rerun'] and not guest_paths:
                status = json.loads((evidence / 'controller_status.json').read_text())
                report = json.loads(contained(evidence, status['report']).read_text())
                folders = missing_foreign_folders(report, self.persona()['identity']['username'])
                if folders:
                    print(f'Managed lab: sample quit after failing to open {folders}; re-running with them created', flush=True)
                    first = evidence
                    evidence = self.task(Path(sample).resolve(), output=output, guest_paths=folders)
                    atomic_json(evidence / 'adaptive_rerun.json', {'previous_run': str(first), 'created_folders': folders,
                                                                   'reason': 'early exit after path-not-found under another user profile'})
                    print(f'Managed evidence retained (adaptive re-run): {evidence}', flush=True)
            status = json.loads((evidence / 'managed_run.json').read_text())
            return status.get('analysis_exit_code', 0)

    def recover(self):
        for path in sorted(self.journals.glob('*.json')):
            if path.stat().st_size > 1048576 or not RUN_PATTERN.fullmatch(path.stem):
                raise RuntimeError('Invalid recovery journal')
            state = json.loads(path.read_text())
            if state.get('cleanup') == 'completed' or state.get('storage') != str(self.storage):
                continue
            resources = RunResources(self.docker, self.journals, self.storage, Path(state['evidence']),
                                     path.stem, existing=state)
            resources.event('recovering_interrupted_run')
            resources.state['status'] = 'interrupted'
            if not resources.cleanup():
                raise RuntimeError('Stale resources could not be cleaned; see the managed journal')
