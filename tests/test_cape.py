import hashlib
from pathlib import Path
from unittest.mock import MagicMock
import pytest
import requests
from core.cape_client import CapeSandboxClient


def response(payload=None, content=b'', status=200, headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.json.return_value = payload
    resp.iter_content.return_value = iter([content])
    resp.__enter__.return_value = resp
    if status >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(str(status))
    return resp


def client(**kwargs):
    session = MagicMock()
    cfg = {'base_url': 'https://cape.example.invalid/apiv2', 'max_artifacts': 20, **kwargs}
    return CapeSandboxClient(cfg, session), session


def test_submit_route_and_single_id(tmp_path):
    cape, session = client(route='inetsim')
    session.post.return_value = response({'error': False, 'data': {'task_ids': [123]}})
    sample = tmp_path / 'sample'
    sample.write_bytes(b'non-executable fixture')
    assert cape.submit_sample(sample) == 123
    kwargs = session.post.call_args.kwargs
    assert kwargs['data']['route'] == 'inetsim'
    assert kwargs['data']['enforce_timeout'] == 'true'
    assert 'route=' not in kwargs['data']['options']
    session.post.return_value = response({'data': {'task_ids': [1, 2]}})
    with pytest.raises(RuntimeError, match='one CAPE task'):
        cape.submit_sample(sample)


def test_report_route_and_wrapped_json(tmp_path):
    cape, session = client()
    session.get.return_value = response(content=b'{"error":false,"data":{"info":{"id":1}}}')
    result = cape.download_json_report(1, tmp_path / 'report.json')
    assert result['data']['info']['id'] == 1
    assert session.get.call_args.args[0].endswith('/tasks/get/report/1/json/')


def test_download_union_dedup_and_hash(tmp_path):
    cape, session = client()
    data = b'short non-PE payload'
    digest = hashlib.sha256(data).hexdigest()
    session.get.return_value = response(content=data)
    report = {'CAPE': {'payloads': [{'sha256': digest}]},
              'procdump': [{'sha256': digest}], 'dropped': [{'sha256': 'invalid'}]}
    paths = cape.download_artifacts(report, tmp_path)
    assert len(paths) == 1 and paths[0].read_bytes() == data
    assert session.get.call_args.args[0].endswith('/files/get/sha256/' + digest + '/')
    assert [r['status'] for r in cape.collection] == ['downloaded', 'duplicate', 'invalid_or_missing_hash']


def test_wrong_hash_and_http_errors_are_not_artifacts(tmp_path):
    cape, session = client()
    session.get.return_value = response(content=b'{"error":true,"error_value":"disabled"}')
    paths = cape.download_artifacts({'CAPE': {'payloads': [{'sha256': 'a'*64}]}}, tmp_path)
    assert not paths
    assert cape.collection[0]['status'] == 'failed'
    assert not list(tmp_path.glob('*.part'))
    assert not list(tmp_path.glob('*.bin'))


def test_limit_and_declared_size(tmp_path):
    cape, session = client(max_artifacts=1)
    session.get.return_value = response(content=b'x', headers={'Content-Length': '999'})
    with pytest.raises(ValueError, match='byte limit'):
        cape._download('/test', tmp_path / 'file.bin', 2)
    session.get.return_value = response(content=b'abc')
    with pytest.raises(ValueError, match='byte limit'):
        cape._download('/test', tmp_path / 'file.bin', 2)
    report = {'CAPE': {'payloads': [{'sha256': 'a'*64}, {'sha256': 'b'*64}]}}
    cape.download_artifacts(report, tmp_path)
    assert cape.collection[-1]['status'] == 'skipped_limit'


def test_pcap_rejects_api_error_json(tmp_path):
    cape, session = client()
    session.get.return_value = response(content=b'{"error":true}')
    cape.download_pcap(1, tmp_path / 'dump.pcap')
    assert cape.collection[-1]['status'] == 'failed'
    assert not (tmp_path / 'dump.pcap').exists()


@pytest.mark.parametrize('payload', [{'error': True}, {'data': {'status': 'failed_reporting'}}, {'data': {}}])
def test_polling_errors(payload):
    cape, session = client()
    session.get.return_value = response(payload)
    with pytest.raises(RuntimeError):
        cape.wait_for_report(1)


def test_reported_and_deadline(monkeypatch):
    cape, session = client(max_wait_seconds=1, poll_interval_seconds=10)
    session.get.return_value = response({'data': {'status': 'reported'}})
    assert cape.wait_for_report(1) == 'reported'
    session.get.return_value = response({'data': {'status': 'running'}})
    times = iter([0, 0, 0.5, 2])
    monkeypatch.setattr('core.cape_client.time.monotonic', lambda: next(times))
    sleeps = []
    monkeypatch.setattr('core.cape_client.time.sleep', sleeps.append)
    with pytest.raises(TimeoutError):
        cape.wait_for_report(1)
    assert sleeps == [0.5]
