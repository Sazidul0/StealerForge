"""Build-time only: fetch pinned official rules and checksum-verified UPX."""
import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path


def tree_hash(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob('*')):
        if path.is_file():
            digest.update(str(path.relative_to(root)).encode() + b'\0')
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def fetch(lock_path, destination):
    lock = json.loads(Path(lock_path).read_text())
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {'lock': lock, 'assets': {}}
    with tempfile.TemporaryDirectory() as temp:
        for name in ('capa_rules', 'capa_signatures', 'cape_yara'):
            spec = lock[name]
            checkout = Path(temp) / name
            checkout.mkdir()
            for args in (["git", "init", "-q"], ["git", "remote", "add", "origin", spec['repository']],
                         ["git", "fetch", "--depth", "1", "--filter=blob:none", "origin", spec['commit']]):
                subprocess.run(args, cwd=checkout, check=True, timeout=300)
            if spec.get('subdirectory'):
                subprocess.run(['git', 'sparse-checkout', 'set', spec['subdirectory']], cwd=checkout, check=True)
            subprocess.run(['git', 'checkout', '--detach', 'FETCH_HEAD'], cwd=checkout, check=True, timeout=300)
            actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=checkout, text=True).strip()
            if actual != spec['commit']:
                raise ValueError('Asset commit mismatch')
            source = checkout / spec.get('subdirectory', '')
            target = destination / name
            shutil.copytree(source, target, ignore=shutil.ignore_patterns('.git'), dirs_exist_ok=True)
            manifest['assets'][name] = {'commit': actual, 'tree_sha256': tree_hash(target)}
        spec = lock['upx']
        archive = Path(temp) / 'upx.tar.xz'
        with urllib.request.urlopen(spec['url'], timeout=60) as response, archive.open('wb') as stream:
            shutil.copyfileobj(response, stream)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != spec['sha256']:
            raise ValueError('UPX release checksum mismatch')
        # Extract just the known regular executable; never unpack arbitrary archive paths.
        with tarfile.open(archive, 'r:xz') as package:
            member = package.getmember(spec['member'])
            if not member.isfile() or member.size > 100_000_000:
                raise ValueError('Unexpected UPX archive member')
            with package.extractfile(member) as source, (destination / 'upx').open('wb') as target:
                shutil.copyfileobj(source, target)
        (destination / 'upx').chmod(0o755)
        manifest['assets']['upx'] = {'version': spec['version'], 'archive_sha256': spec['sha256'],
                                    'binary_sha256': hashlib.sha256((destination / 'upx').read_bytes()).hexdigest()}
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--lock', required=True)
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    fetch(args.lock, args.destination)
