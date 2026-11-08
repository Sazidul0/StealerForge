"""Check effective runtime controls on harmless processes; not an escape resistance test."""
import os
import socket
from pathlib import Path

import pytest


@pytest.mark.skipif(not Path('/opt/assets/manifest.json').is_file(), reason='Requires the Compose test container')
def test_effective_container_controls():
    assert os.getuid() != 0
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    assert int(status['CapEff'].strip(), 16) == 0
    assert status['NoNewPrivs'].strip() == '1'
    assert status['Seccomp'].strip() == '2'
    assert {name for _, name in socket.if_nameindex()} == {'lo'}
    mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    root = next(m for m in mounts if m[4] == '/')
    assert 'ro' in root[5].split(',')
    temporary = next(m for m in mounts if m[4] == '/tmp')
    assert {'noexec', 'nosuid', 'nodev'} <= set(temporary[5].split(','))
    assert temporary[temporary.index('-') + 1] == 'tmpfs'
    assert not Path('/var/run/docker.sock').exists()
