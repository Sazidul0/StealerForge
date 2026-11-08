"""Read-only host prerequisite checks for managed Windows/CAPE deployment."""
import argparse
import json
import platform
import shutil
import stat
import subprocess
from pathlib import Path

GIB = 1024 ** 3


def inspect_storage(directory, minimum_gib):
    path = Path(directory).expanduser().resolve()
    ancestor = path
    while not ancestor.exists():
        ancestor = ancestor.parent
    if not ancestor.is_dir():
        raise ValueError('Storage path or its existing parent is not a directory')
    free = shutil.disk_usage(ancestor).free
    return {'status': 'passed' if free >= minimum_gib * GIB else 'blocked',
            'requested_directory': str(path), 'filesystem_checked_at': str(ancestor),
            'free_gib': round(free / GIB, 2), 'required_free_gib': minimum_gib,
            'note': 'Project capacity budget for Windows, controller, snapshots and results; '
                    'this is not the compressed Windows download size.'}


def inspect_memory(minimum_gib, path=Path('/proc/meminfo')):
    fields = dict(line.split(':', 1) for line in path.read_text().splitlines())
    available = int(fields['MemAvailable'].split()[0]) * 1024
    return {'status': 'passed' if available >= minimum_gib * GIB else 'blocked',
            'available_gib': round(available / GIB, 2), 'required_available_gib': minimum_gib}


def inspect_kvm(path=Path('/dev/kvm')):
    try:
        valid = stat.S_ISCHR(path.stat().st_mode)
    except FileNotFoundError:
        valid = False
    return {'status': 'passed' if valid else 'blocked', 'device': str(path),
            'note': 'Device presence only; use --probe-docker-kvm to verify access through Docker.'
                    if valid else 'KVM device missing. On this Intel host, an administrator can run sudo modprobe kvm_intel.'}


def docker_server():
    result = subprocess.run(['docker', 'info', '--format', '{{json .}}'],
                            capture_output=True, text=True, timeout=20, check=False)
    if result.returncode:
        return {'status': 'blocked', 'error': 'Cannot access the Docker daemon from this process.'}
    info = json.loads(result.stdout)
    return {'status': 'passed' if info.get('OSType') == 'linux' else 'blocked',
            'os_type': info.get('OSType'), 'server_version': info.get('ServerVersion')}


def probe_docker_kvm():
    # A harmless API-version ioctl; no VM is created, image pulled, or network opened.
    probe = ('import os,fcntl; fd=os.open("/dev/kvm",os.O_RDWR); '
             'v=fcntl.ioctl(fd,0xAE00,0); os.close(fd); print(v); raise SystemExit(0 if v==12 else 1)')
    command = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
               '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
               '--pids-limit', '16', '--memory', '128m', '--user', '0:0', '--device', '/dev/kvm',
               '--entrypoint', '/opt/core/bin/python', 'stealerforge-analysis:local', '-c', probe]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    return {'status': 'passed' if result.returncode == 0 and result.stdout.strip() == '12' else 'blocked',
            'note': 'Expected Linux KVM API version 12 using the existing analysis image.',
            'returncode': result.returncode, 'output': result.stdout.strip()[:200],
            'error': result.stderr.strip()[:1000]}


def check_host(storage, minimum_free_gib=80, minimum_available_gib=8, probe=False):
    if minimum_free_gib <= 0 or minimum_available_gib <= 0:
        raise ValueError('Resource budgets must be positive')
    checks = {'platform': {'status': 'passed' if platform.system() == 'Linux' and
                          platform.machine() in ('x86_64', 'amd64') else 'blocked',
                          'system': platform.system(), 'architecture': platform.machine()}}
    for name, operation in (
        ('storage', lambda: inspect_storage(storage, minimum_free_gib)),
        ('memory', lambda: inspect_memory(minimum_available_gib)),
        ('kvm_device', inspect_kvm), ('docker', docker_server),
    ):
        try:
            checks[name] = operation()
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
            checks[name] = {'status': 'blocked', 'error': f'{type(exc).__name__}: {exc}'}
    if probe:
        if checks['kvm_device']['status'] != 'passed' or checks['docker']['status'] != 'passed':
            checks['docker_kvm'] = {'status': 'blocked', 'note': 'KVM device and Docker access must pass first.'}
        else:
            try:
                checks['docker_kvm'] = probe_docker_kvm()
            except (OSError, subprocess.TimeoutExpired) as exc:
                checks['docker_kvm'] = {'status': 'blocked', 'error': str(exc)}
    return {'status': 'prerequisites_met' if all(c['status'] == 'passed' for c in checks.values()) else 'blocked',
            'checks': checks,
            'deployment_status': 'not_provisioned_or_validated_by_this_check',
            'note': 'This checks host prerequisites only. Windows installation, CAPE integration, '
                    'guest isolation, telemetry and clean-state restoration still require validation.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--storage', type=Path, default=Path('lab-data'))
    parser.add_argument('--min-free-gib', type=int, default=80)
    parser.add_argument('--min-available-gib', type=int, default=8)
    parser.add_argument('--probe-docker-kvm', action='store_true')
    args = parser.parse_args(argv)
    if args.min_free_gib <= 0 or args.min_available_gib <= 0:
        parser.error('Resource budgets must be positive')
    report = check_host(args.storage, args.min_free_gib, args.min_available_gib, args.probe_docker_kvm)
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'prerequisites_met' else 1


if __name__ == '__main__':
    raise SystemExit(main())
