"""Bounded single-level ZIP intake. Never use archive paths as output paths."""
import hashlib
import os
import stat
import tempfile
from pathlib import Path, PurePosixPath

import pyzipper

from core.evidence import sha256_file


def inspect_archive(path, cfg):
    path = Path(path)
    if path.stat().st_size > cfg['max_archive_bytes']:
        raise ValueError('Archive exceeds compressed byte limit')
    with pyzipper.AESZipFile(str(path)) as archive:
        entries = archive.infolist()
        if len(entries) > cfg['max_members']:
            raise ValueError('Archive has too many members')
        names, result, total = set(), [], 0
        for item in entries:
            name = item.filename
            normalized = name.replace('\\', '/')
            parts = PurePosixPath(normalized)
            mode = item.external_attr >> 16
            if (parts.is_absolute() or '..' in parts.parts or ':' in normalized or '\x00' in name
                    or normalized in names or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
                raise ValueError('Unsafe, duplicate, or special archive member')
            names.add(normalized)
            total += item.file_size
            if (total > cfg['max_total_bytes'] or item.file_size > cfg['max_member_bytes']
                    or item.file_size / max(1, item.compress_size) > cfg['max_ratio']):
                raise ValueError('Archive expansion exceeds configured limits')
            result.append({'name': name, 'size_bytes': item.file_size, 'compressed_bytes': item.compress_size,
                           'encrypted': bool(item.flag_bits & 1), 'directory': item.is_dir()})
    return {'archive_sha256': sha256_file(path), 'members': result, 'declared_total_bytes': total}


def extract_member(path, member, directory, cfg, password=None):
    inventory = inspect_archive(path, cfg)
    candidates = [m for m in inventory['members'] if not m['directory']]
    if member is None:
        if len(candidates) != 1:
            raise ValueError('Select --archive-member explicitly when an archive has multiple files')
        member = candidates[0]['name']
    entry = next((m for m in candidates if m['name'] == member), None)
    if entry is None:
        raise ValueError('Selected archive member is missing or is a directory')
    if entry['encrypted'] and not password:
        raise ValueError('Encrypted archive requires the configured archive password environment variable')
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.intake-', dir=directory)
    temporary = Path(name)
    digest, size = hashlib.sha256(), 0
    try:
        with os.fdopen(fd, 'wb') as target, pyzipper.AESZipFile(str(path)) as archive:
            with archive.open(member, pwd=password.encode() if password else None) as source:
                while chunk := source.read(65536):
                    size += len(chunk)
                    if size > cfg['max_member_bytes'] or size > entry['size_bytes']:
                        raise ValueError('Archive member exceeded declared or configured size')
                    target.write(chunk)
                    digest.update(chunk)
        if size != entry['size_bytes']:
            raise ValueError('Archive member size mismatch')
        with temporary.open('rb') as source:
            magic = source.read(8)
        if magic.startswith((b'PK\x03\x04', b'PK\x05\x06', b'7z\xbc\xaf\x27\x1c', b'Rar!', b'\x1f\x8b')):
            raise ValueError('Nested archive intake is disabled')
        destination = directory / (digest.hexdigest() + '.bin')
        if destination.exists():
            raise ValueError('Intake destination already exists')
        temporary.replace(destination)
        return destination, {'archive_sha256': inventory['archive_sha256'], 'member': member,
                             'payload_sha256': digest.hexdigest(), 'size_bytes': size,
                             'note': 'Decrypted bytes retained as non-executable data; not launched by intake'}
    finally:
        temporary.unlink(missing_ok=True)
