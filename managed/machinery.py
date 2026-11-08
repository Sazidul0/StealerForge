"""CAPE adapter for a single fresh Docker/QEMU guest. Never reuses a dirty guest."""
import os
import sys
import time

sys.path.insert(0, '/opt/stealerforge-managed')
from qmp import execute
from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError

SOCKET = '/qmp/control.sock'


class Stealerforge(Machinery):
    module_name = 'stealerforge'

    def __init__(self):
        super().__init__()
        self.used = False

    def _initialize_check(self):
        if execute(SOCKET, 'query-status')['status'] not in ('running', 'paused'):
            raise CuckooMachineError('Managed guest is not ready')

    def _list(self):
        return ['windows']

    def start(self, label):
        if label != 'windows' or self.used:
            raise CuckooMachineError('Only one analysis per disposable guest is allowed')
        self.used = True
        status = execute(SOCKET, 'query-status')['status']
        if status == 'paused':
            execute(SOCKET, 'cont')
        elif status != 'running':
            raise CuckooMachineError(f'Guest state is {status}')

    def stop(self, label):
        try:
            execute(SOCKET, 'quit')
        except (FileNotFoundError, ConnectionRefusedError):
            return
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                execute(SOCKET, 'query-status', timeout=1)
            except (FileNotFoundError, ConnectionRefusedError, ConnectionResetError):
                return
            time.sleep(0.2)
        raise CuckooMachineError('QEMU did not terminate')

    def _status(self, label):
        try:
            status = execute(SOCKET, 'query-status')['status']
            return 'running' if status == 'running' else 'paused'
        except (FileNotFoundError, ConnectionRefusedError):
            return 'stopped'

    def screenshot(self, label, path):
        # Taken by QEMU on the host side: nothing runs in the guest, so samples cannot observe it.
        from PIL import Image
        frame = '/evidence/.screen.png'
        execute(SOCKET, 'screendump', {'filename': frame, 'format': 'png'}, timeout=10)
        with Image.open(frame) as image:
            image.convert('RGB').save(path, 'JPEG', quality=60)
        os.unlink(frame)

    def dump_memory(self, label, path):
        # The Windows launcher has this run's evidence directory mounted at /evidence.
        destination = '/evidence/guest-memory.elf'
        execute(SOCKET, 'dump-guest-memory', {'paging': False, 'protocol': 'file:' + destination}, timeout=120)
        os.link(destination, path)
