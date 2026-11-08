"""Read-only readiness checks and a fail-closed gate for new CAPE submissions."""
import hashlib
import json
import os
import shutil
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from core.config import credential
from core.evidence import write_json
from core.process_runner import run_bounded


def container_controls():
    checks = {}
    try:
        status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        checks.update(nonroot=os.getuid() != 0, capabilities_dropped=int(status['CapEff'].strip(), 16) == 0,
                      no_new_privileges=status['NoNewPrivs'].strip() == '1', seccomp=status['Seccomp'].strip() == '2',
                      network_disabled={name for _, name in socket.if_nameindex()} == {'lo'},
                      no_docker_socket=not Path('/var/run/docker.sock').exists())
        root = next(line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4] == '/')
        checks['readonly_root'] = 'ro' in root[5].split(',')
    except (OSError, KeyError, StopIteration, AttributeError, ValueError):
        checks['runtime_inspection'] = False
    return checks


def lab_acceptance(cfg):
    lab, cape = cfg['lab'], cfg['cape']
    path = Path(lab['acceptance_file']) if lab['acceptance_file'] else None
    if path is None or not path.is_file() or path.stat().st_size > 1048576:
        raise ValueError('Live submission requires a fresh lab acceptance record; see lab/README.md')
    data = json.loads(path.read_text())
    timestamp = datetime.fromisoformat(data['validated_at_utc'].replace('Z', '+00:00'))
    age = (datetime.now(timezone.utc) - timestamp).total_seconds()
    if not 0 <= age <= lab['acceptance_max_age_hours'] * 3600:
        raise ValueError('Lab acceptance record is stale or dated in the future')
    expected = {'cape_base_url': cape['base_url'].rstrip('/'), 'machine': cape.get('machine', ''),
                'snapshot': lab['snapshot'], 'route': cape.get('route')}
    if not expected['machine'] or not expected['snapshot'] or expected['route'] != 'inetsim':
        raise ValueError('Live submission requires a named machine, snapshot and inetsim route')
    if any(data.get(key) != value for key, value in expected.items()):
        raise ValueError('Lab acceptance does not match the configured deployment')
    required = ('host_controls', 'guest_isolation', 'simulated_network', 'snapshot_restore', 'benign_telemetry')
    if any(data.get('checks', {}).get(key) is not True for key in required):
        raise ValueError('Lab acceptance has missing or failed checks')
    # Require the source observations to remain available and unchanged.
    if not isinstance(data.get('sources'), list) or len(data['sources']) < 3:
        raise ValueError('Lab acceptance lacks source observations')
    for source in data['sources']:
        source_path = path.parent / source['path']
        if not source_path.is_file() or source_path.stat().st_size > 16777216:
            raise ValueError('Lab acceptance source is unavailable or too large')
        if hashlib.sha256(source_path.read_bytes()).hexdigest() != source['sha256']:
            raise ValueError('Lab acceptance source hash mismatch')
    return data


def check_live(cfg, client, require_acceptance=True):
    if require_acceptance:
        lab_acceptance(cfg)
    parsed = urlparse(cfg['cape']['base_url'])
    if parsed.scheme != 'https' and parsed.hostname not in ('127.0.0.1', '::1', 'localhost'):
        raise ValueError('Use HTTPS or a loopback SSH tunnel for live CAPE access')
    if not credential(cfg['cape'], 'api_token', 'api_token_env', 'CAPE_API_TOKEN'):
        raise ValueError('Authenticated CAPE access requires CAPE_API_TOKEN')
    client.check_health()
    machines = client.list_machines()
    name = cfg['cape'].get('machine', '')
    machine = next((m for m in machines if m.get('name') == name or m.get('label') == name), None)
    if not machine or str(machine.get('platform', '')).lower() != 'windows':
        raise ValueError('Configured Windows machine is not present in CAPE')
    if machine.get('locked') or machine.get('status') in ('running', 'error'):
        raise ValueError('Configured machine is busy or unavailable')
    if require_acceptance and machine.get('snapshot') != cfg['lab']['snapshot']:
        raise ValueError('CAPE machine snapshot differs from the validated snapshot')
    if 'inetsim' not in client.list_routes():
        raise ValueError('CAPE does not advertise the inetsim route')
    return {'machine': name, 'snapshot': machine.get('snapshot'), 'route': 'inetsim'}


def run_preflight(cfg, include_cape=False):
    checks = []
    def record(name, fn):
        try:
            value = fn()
            checks.append({'name': name, 'status': 'passed', 'details': value})
        except Exception as exc:
            checks.append({'name': name, 'status': 'failed', 'error': f'{type(exc).__name__}: {exc}'})
    def storage():
        path = Path(cfg['output']['directory'])
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile(dir=path) as stream:
            stream.write(b'probe')
        free = shutil.disk_usage(path).free
        if free < cfg['output']['min_free_bytes']:
            raise ValueError('Output volume has insufficient free space')
        return {'free_bytes': free}
    record('output_storage', storage)
    if cfg['safety']['require_container_controls']:
        def isolation():
            result = container_controls()
            if not all(result.values()):
                raise ValueError('Required runtime controls failed: ' + ', '.join(k for k,v in result.items() if not v))
            return result
        record('container_controls', isolation)
    if cfg['local_analysis']['enabled']:
        def engines():
            settings = cfg['local_analysis']
            with tempfile.TemporaryDirectory(prefix='stealerforge-preflight-') as temp:
                directory = Path(temp)
                write_json(directory / 'options.json', settings)
                execution = run_bounded([settings['python_path'] or os.sys.executable,
                                         str(Path(__file__).with_name('engine_worker.py')), 'inventory',
                                         '--options', str(directory / 'options.json'), '--output', temp],
                                        directory, timeout=60, memory_mb=settings['memory_mb'])
                if execution['status'] != 'completed':
                    raise ValueError('Engine inventory worker failed; verify its interpreter and dependencies')
                result = json.loads((directory / 'result.json').read_text())
                if result.get('status') != 'completed':
                    raise ValueError('Parser imports failed: ' + json.dumps(result.get('parser_import_checks', [])))
                return result
        record('engine_imports', engines)
        if cfg['local_analysis'].get('cape_yara_path'):
            def yara_assets():
                import yara
                paths = sorted(p for p in Path(cfg['local_analysis']['cape_yara_path']).rglob('*')
                               if p.suffix in ('.yar', '.yara') and 'deprecated' not in p.parts)
                if not paths:
                    raise ValueError('No CAPE rules found')
                for path in paths:
                    yara.compile(filepath=str(path), externals={'filename': ''})
                return {'files_compiled': len(paths)}
            record('cape_rules', yara_assets)
    for section, key in [('local_analysis','upx_path'), ('enrichment','capa_path'), ('enrichment','floss_path')]:
        executable = cfg[section].get(key)
        if not executable:
            continue
        def version(executable=executable):
            with tempfile.TemporaryDirectory() as temp:
                result = run_bounded([executable, '--version'], temp, timeout=30)
                if result['status'] != 'completed':
                    raise ValueError('Executable version check failed')
                return {'version_output': (Path(temp) / 'stdout.log').read_text()[:1024]}
        record(key, version)
    for key in ('capa_rules_path', 'capa_signatures_path'):
        if cfg['enrichment'].get('capa_path'):
            def asset(key=key):
                path = Path(cfg['enrichment'].get(key, ''))
                if not cfg['enrichment'].get(key) or not path.is_dir() or not any(p.is_file() for p in path.rglob('*')):
                    raise ValueError('Required capa data directory is missing or empty')
                return str(path)
            record(key, asset)
    if include_cape:
        def live():
            from core.cape_client import CapeSandboxClient
            client = CapeSandboxClient(cfg['cape'])
            try:
                return check_live(cfg, client)
            finally:
                client.close()
        record('live_lab', live)
    return {'status': 'passed' if all(c['status'] == 'passed' for c in checks) else 'failed',
            'checks': checks, 'note': 'Point-in-time checks do not prove escape resistance or malware coverage'}
