"""StealerForge analyzer module: export the complete Sysmon channel once, when the analysis stops.

CAPE's evtx module wipes channels at start-up (after the sample may already be running) and between periodic
snapshots, which loses Sysmon events. The Sysmon channel is therefore removed from that module and exported
here without any wiping; the host keeps only events from the sample's process tree.
"""
import logging
import os
import subprocess
import tempfile

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)


class SysmonExport(Auxiliary):
    stop_priority = 10

    def __init__(self, options=None, config=None):
        Auxiliary.__init__(self, options, config)
        self.startupinfo = subprocess.STARTUPINFO()
        self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    def start(self):
        return True

    def stop(self):
        path = os.path.join(tempfile.gettempdir(), 'sf-sysmon.evtx')
        try:
            subprocess.call(['wevtutil.exe', 'epl', 'Microsoft-Windows-Sysmon/Operational', path, '/ow:true'],
                            startupinfo=self.startupinfo, timeout=120)
            if os.path.exists(path):
                upload_to_host(path, 'sysmon/sysmon.evtx')
            else:
                log.error('Sysmon export produced no file')
        except Exception as exc:
            log.error('Sysmon export failed: %s', exc)
        return True
