"""Run exactly one CAPE task and retain raw evidence; no API or shared database."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import time

from configure import configure

ROOT = Path('/opt/CAPEv2')
EVIDENCE = Path('/evidence')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sealed_namespace():
    names = {name for _, name in socket.if_nameindex()}
    if 'lo' not in names or names - {'lo', 'sfsink0'}:
        raise RuntimeError('Managed controller requires the sealed analysis namespace (loopback and sink device only)')
    if 'sfsink0' in names:
        details = subprocess.run(['ip', '-d', 'link', 'show', 'sfsink0'], capture_output=True, text=True, timeout=10).stdout
        if '\n    dummy ' not in details:
            raise RuntimeError('sfsink0 must be a dummy device without carrier')


def without_harness_traffic(source, target):
    """Copy the capture for CAPE minus guest-agent (8000) and result-server (2042) flows, which are not sample traffic."""
    import dpkt
    kept = dropped = 0
    with source.open('rb') as stream, target.open('wb') as output:
        reader = dpkt.pcap.Reader(stream)
        # dpkt defaults to snaplen 1500; libpcap readers (Suricata, tcpdump) reject the first 1514-byte frame.
        writer = dpkt.pcap.Writer(output, snaplen=max(reader.snaplen, 262144), linktype=reader.datalink())
        for timestamp, frame in reader:
            try:
                packet = dpkt.ethernet.Ethernet(frame).data
                segment = packet.data if isinstance(packet, dpkt.ip.IP) else None
                if (isinstance(segment, dpkt.tcp.TCP) and {segment.sport, segment.dport} & {8000, 2042}
                        and socket.inet_ntoa(packet.src).startswith('10.0.2.') and socket.inet_ntoa(packet.dst).startswith('10.0.2.')):
                    dropped += 1
                    continue
            except (dpkt.UnpackError, OSError):
                pass
            writer.writepkt(frame, timestamp)
            kept += 1
    return {'kept_packets': kept, 'harness_packets_removed': dropped}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--deadline', type=int, default=900)
    parser.add_argument('--options', default='procmemdump=1,import_reconstruction=1')
    args = parser.parse_args()
    result = {'status': 'initializing', 'task_id': None}
    scheduler = None
    try:
        sealed_namespace()
        configure(timeout=args.timeout)
        sys.path.insert(0, str(ROOT))
        os.chdir(ROOT)
        from lib.cuckoo.core.database import Database, init_database
        init_database()
        db = Database()
        # Not enforced: the task ends when every monitored process has exited, or at the timeout.
        with db.session.begin():
            task_id = db.add_path(file_path='/input/sample.bin', timeout=args.timeout,
                                  machine='windows', platform='windows', route='none',
                                  enforce_timeout=False, options=args.options)
        if not task_id:
            raise RuntimeError('CAPE did not create a task')
        result.update(status='submitted', task_id=task_id, input_sha256=digest(Path('/input/sample.bin')))
        (EVIDENCE / 'controller_status.json').write_text(json.dumps(result, indent=2))
        with (EVIDENCE / 'cape-scheduler.log').open('wb') as log:
            scheduler = subprocess.Popen([sys.executable, 'cuckoo.py', '-m', '1'], stdout=log,
                                         stderr=subprocess.STDOUT, start_new_session=True)
            scheduler.wait(timeout=args.deadline)
        if scheduler.returncode:
            raise RuntimeError(f'CAPE scheduler exited with {scheduler.returncode}; inspect cape-scheduler.log')
        # The session keeps the submitted Task cached (expire_on_commit=False); reload what the scheduler wrote.
        db.session.expire_all()
        with db.session.begin():
            task = db.view_task(task_id)
            status = task.status if task else None
        if status not in ('completed', 'reported'):
            raise RuntimeError(f'CAPE task ended in {status}')
        analysis = EVIDENCE / 'cape/analyses' / str(task_id)
        if (EVIDENCE / 'guest.pcap').is_file():
            result['pcap_filter'] = without_harness_traffic(EVIDENCE / 'guest.pcap', analysis / 'dump.pcap')
        with (EVIDENCE / 'cape-processing.log').open('wb') as log:
            subprocess.run([sys.executable, 'utils/process.py', '-r', str(task_id)],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=args.deadline)
        report = analysis / 'reports/report.json'
        if not report.is_file():
            raise RuntimeError('CAPE processing did not create report.json')
        payloads = []
        for directory in ('CAPE', 'procdump', 'files', 'memory'):
            root = analysis / directory
            if not root.is_dir():
                continue
            for path in sorted(root.rglob('*')):
                if path.is_symlink() or not path.is_file() or path.suffix == '.json':
                    continue
                # memory/ also holds whole-process .dmp files; keep only the PE images CAPE carved from them,
                # and skip header-only pages.
                if directory == 'memory' and (not re.fullmatch(r'\d+_0x[0-9a-f]+', path.name) or path.stat().st_size <= 4096):
                    continue
                payloads.append({'path': str(path.relative_to(EVIDENCE)),
                                 'size_bytes': path.stat().st_size, 'sha256': digest(path)})
        result.update(status='completed', report=str(report.relative_to(EVIDENCE)), artifacts=payloads,
                      report_sha256=digest(report),
                      note='No real network. Simulated internet (fake DNS, TLS interception, canned HTTP/SMTP/FTP responses); '
                           'family-specific C2 replies are not emulated, except the plain-text DDoS-bot "REGISTER" protocol.')
        return 0
    except BaseException as exc:
        result.update(status='failed', error=f'{type(exc).__name__}: {exc}')
        return 1
    finally:
        if scheduler is not None and scheduler.poll() is None:
            os.killpg(scheduler.pid, signal.SIGKILL)
            scheduler.wait()
        database = ROOT / 'db/cuckoo.db'
        if database.is_file():
            try:
                with sqlite3.connect(database) as source, sqlite3.connect(EVIDENCE / 'cape.sqlite') as target:
                    source.backup(target)
            except sqlite3.Error as exc:
                result['database_backup_error'] = str(exc)
        (EVIDENCE / 'controller_status.json').write_text(json.dumps(result, indent=2))


if __name__ == '__main__':
    raise SystemExit(main())
