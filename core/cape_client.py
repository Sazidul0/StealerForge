"""CAPE API v2 client with bounded downloads and explicit collection outcomes."""
import hashlib
import json
import re
import time
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.config import credential, require_live_cape
from core.evidence import cape_section, unwrap_report


class CapeSandboxClient:
    def __init__(self, cfg, session=None):
        require_live_cape(cfg)
        self.cfg = cfg
        self.base_url = cfg['base_url'].rstrip('/')
        self.session = session or requests.Session()
        token = credential(cfg, 'api_token', 'api_token_env', 'CAPE_API_TOKEN')
        if token:
            self.session.headers.update({'Authorization': f'Token {token}'})
        # Submission is intentionally never retried: a timeout may have created a task.
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 502, 503, 504], allowed_methods=['GET'])
        self.session.mount('http://', HTTPAdapter(max_retries=retry))
        self.session.mount('https://', HTTPAdapter(max_retries=retry))
        self.request_timeout = cfg.get('request_timeout_seconds', 30)
        self.collection = []

    @staticmethod
    def _checked_json(response):
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or payload.get('error'):
            raise RuntimeError('CAPE returned an API error or malformed response; check server permissions and logs')
        return payload

    def _get_json(self, endpoint):
        with self.session.get(self.base_url + endpoint, timeout=self.request_timeout, allow_redirects=False) as resp:
            if 300 <= resp.status_code < 400:
                raise RuntimeError('Unexpected CAPE redirect; configure the final API URL')
            return self._checked_json(resp)

    def check_health(self):
        return self._get_json('/cuckoo/status/')

    def list_machines(self):
        data = self._get_json('/machines/list/').get('data')
        if not isinstance(data, list) or any(not isinstance(m, dict) for m in data):
            raise ValueError('Malformed CAPE machine inventory')
        return data

    def list_routes(self):
        data = self._get_json('/exitnodes/').get('data')
        if not isinstance(data, list):
            raise ValueError('Malformed CAPE route inventory')
        return data

    def submit_sample(self, file_path):
        data = {'timeout': self.cfg.get('timeout_seconds', 180),
                'enforce_timeout': 'true' if self.cfg.get('enforce_timeout', True) else 'false',
                'options': self.cfg.get('options', 'procmemdump=1,import_reconstruction=1'),
                'route': self.cfg.get('route', 'inetsim'), 'platform': 'windows'}
        for src, dest in [('vm_tags', 'tags'), ('package', 'package'), ('machine', 'machine')]:
            if self.cfg.get(src):
                data[dest] = self.cfg[src]
        with Path(file_path).open('rb') as stream:
            with self.session.post(self.base_url + '/tasks/create/file/',
                                   files={'file': (Path(file_path).name, stream)}, data=data,
                                   timeout=self.request_timeout, allow_redirects=False) as response:
                payload = self._checked_json(response)
        body = payload.get('data', payload)
        ids = body.get('task_ids') or [body.get('task_id')]
        if len(ids) != 1 or not str(ids[0]).isdigit() or int(ids[0]) <= 0:
            raise RuntimeError('Expected one CAPE task ID; submission may have created multiple tasks. Inspect CAPE before retrying.')
        return int(ids[0])

    def wait_for_report(self, task_id):
        deadline = time.monotonic() + self.cfg.get('max_wait_seconds', 900)
        while time.monotonic() < deadline:
            payload = self._get_json(f'/tasks/view/{int(task_id)}/')
            body = payload.get('data', payload.get('task', payload))
            status = body.get('status')
            if not isinstance(status, str):
                raise RuntimeError('CAPE task response has no status')
            if status == 'reported':
                return status
            if status.startswith('failed') or status in ('banned', 'deleted'):
                raise RuntimeError(f'CAPE task {task_id} ended with {status}')
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(self.cfg.get('poll_interval_seconds', 10), remaining))
        raise TimeoutError(f'CAPE task {task_id} exceeded max_wait_seconds; reuse --task-id to resume')

    def _download(self, endpoint, destination, limit, expected_hash=None, pcap=False):
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_suffix(destination.suffix + '.part')
        digest, size = hashlib.sha256(), 0
        try:
            with self.session.get(self.base_url + endpoint, timeout=self.request_timeout,
                                  stream=True, allow_redirects=False) as response:
                response.raise_for_status()
                if response.status_code != 200:
                    raise RuntimeError(f'Unexpected download status {response.status_code}')
                if int(response.headers.get('Content-Length', '0')) > limit:
                    raise ValueError('Download exceeds configured byte limit')
                with partial.open('wb') as stream:
                    for chunk in response.iter_content(65536):
                        if not chunk:
                            continue
                        size += len(chunk)
                        if size > limit:
                            raise ValueError('Download exceeds configured byte limit')
                        stream.write(chunk)
                        digest.update(chunk)
            if expected_hash and digest.hexdigest() != expected_hash.lower():
                raise ValueError('Downloaded artifact SHA256 does not match report metadata')
            if pcap:
                with partial.open('rb') as stream:
                    magic = stream.read(4)
                if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1',
                                 b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a'):
                    raise ValueError('Downloaded response is not a PCAP/PCAPNG file')
            partial.replace(destination)
            return {'size_bytes': size, 'sha256': digest.hexdigest()}
        finally:
            partial.unlink(missing_ok=True)

    def download_json_report(self, task_id, save_path):
        path = Path(save_path)
        self._download(f'/tasks/get/report/{int(task_id)}/json/', path,
                       self.cfg.get('max_report_bytes', 268435456))
        report = json.loads(path.read_text(encoding='utf-8'))
        unwrap_report(report)
        return report

    def download_artifacts(self, raw_report, dump_dir, include_dropped=True):
        report, prefix = unwrap_report(raw_report)
        ckey = 'CAPE' if report.get('CAPE') else 'cape'
        candidates = []
        if self.cfg.get('download_unpacked_payloads', True):
            candidates.extend(('payload', item, f'{prefix}/{ckey}/payloads/{i}')
                              for i, item in enumerate(cape_section(report).get('payloads') or []))
            candidates.extend(('procdump', item, f'{prefix}/procdump/{i}')
                              for i, item in enumerate(report.get('procdump') or []))
        if include_dropped and self.cfg.get('download_dropped_files', True):
            candidates.extend(('dropped', item, f'{prefix}/dropped/{i}')
                              for i, item in enumerate(report.get('dropped') or []))
        seen, downloaded, attempted = set(), [], 0
        for kind, item, pointer in candidates:
            sha = str(item.get('sha256', '')).lower() if isinstance(item, dict) else ''
            record = {'kind': kind, 'sha256': sha, 'source': 'raw_cape_report.json#' + pointer}
            self.collection.append(record)
            if not re.fullmatch(r'[a-f0-9]{64}', sha):
                record['status'] = 'invalid_or_missing_hash'
                continue
            if sha in seen:
                record['status'] = 'duplicate'
                continue
            seen.add(sha)
            if attempted >= self.cfg.get('max_artifacts', 20):
                record['status'] = 'skipped_limit'
                continue
            attempted += 1
            path = Path(dump_dir) / f'{sha}.bin'
            try:
                details = self._download(f'/files/get/sha256/{sha}/', path,
                                         self.cfg.get('max_download_bytes', 134217728), expected_hash=sha)
                record.update(details, status='downloaded', path=f'{Path(dump_dir).name}/{path.name}')
                downloaded.append(path)
            except (requests.RequestException, ValueError, RuntimeError, OSError) as exc:
                record.update(status='failed', error=str(exc))
        return downloaded

    def download_unpacked_payloads(self, raw_report, dump_dir, max_dumps=None):
        # Compatibility entry point; preserves the configured limit unless explicitly supplied.
        old = self.cfg.get('max_artifacts', 20)
        try:
            if max_dumps is not None:
                self.cfg['max_artifacts'] = max_dumps
            return self.download_artifacts(raw_report, dump_dir, include_dropped=False)
        finally:
            self.cfg['max_artifacts'] = old

    def download_pcap(self, task_id, destination):
        record = {'kind': 'pcap', 'task_id': task_id}
        self.collection.append(record)
        try:
            details = self._download(f'/tasks/get/pcap/{int(task_id)}/', destination,
                                     self.cfg.get('max_download_bytes', 134217728), pcap=True)
            record.update(details, status='downloaded', path=Path(destination).name)
        except (requests.RequestException, ValueError, RuntimeError, OSError) as exc:
            record.update(status='failed', error=str(exc))

    def close(self):
        self.session.close()

    def download_forensics(self, task_id, directory):
        directory = Path(directory)
        downloaded = []
        for enabled, kind, endpoint in [
            ('download_evtx', 'evtx_bundle', 'evtx'),
            ('download_process_memory', 'process_memory_bundle', 'procmemory'),
            ('download_full_memory', 'full_memory', 'fullmemory')]:
            if not self.cfg.get(enabled):
                continue
            record = {'kind': kind, 'task_id': task_id}
            self.collection.append(record)
            path = directory / (kind + '.bin')
            try:
                details = self._download(f'/tasks/get/{endpoint}/{int(task_id)}/', path,
                                         self.cfg.get('max_forensic_bytes', 536870912))
                with path.open('rb') as stream:
                    prefix = stream.read(512)
                if not prefix or prefix.lstrip().startswith((b'{', b'<')):
                    raise ValueError('Forensic endpoint returned empty data or an API/web error')
                if kind.endswith('_bundle') and not prefix.startswith(b'PK'):
                    raise ValueError('Expected a ZIP forensic bundle')
                record.update(details, status='downloaded', path=f'{directory.name}/{path.name}',
                              note='Server artifact retained; no independent expected hash supplied')
                downloaded.append((path, kind))
            except (requests.RequestException, ValueError, RuntimeError, OSError) as exc:
                path.unlink(missing_ok=True)
                record.update(status='failed', error=str(exc))
        return downloaded
