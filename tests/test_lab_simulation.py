import base64
import gzip
import io
import json
import socket
import struct
import zipfile

import pytest

from core.canaries import scan_netsim
from managed import netsim
from managed.persona import canary_strings, generate


def dns_query(name, qtype=1):
    question = b''.join(bytes([len(part)]) + part.encode() for part in name.split('.')) + b'\0'
    return b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + question + struct.pack('!HH', qtype, 1)


class Memory:
    def __init__(self):
        self.events = []

    def event(self, kind, **values):
        self.events.append({'kind': kind, **values})

    def blob(self, data):
        return {'size': len(data)} if data else None


def test_fake_dns_gives_stable_unrouted_addresses_and_the_windows_connectivity_answer():
    names, recorder = netsim.Names(), Memory()
    reply = netsim.dns_answer(dns_query('c2.example.top'), names, recorder, 'udp')
    address = socket.inet_ntoa(reply[-4:])
    assert reply[:2] == b'\x12\x34' and struct.unpack('!H', reply[6:8])[0] == 1
    assert netsim.SINK_POOL.supernet_of(__import__('ipaddress').ip_network(address))
    assert netsim.dns_answer(dns_query('c2.example.top'), names, recorder, 'udp')[-4:] == reply[-4:]
    assert names.name_for(address) == 'c2.example.top'
    ncsi = netsim.dns_answer(dns_query('dns.msftncsi.com'), names, recorder, 'udp')
    assert socket.inet_ntoa(ncsi[-4:]) == '131.107.255.255'
    assert struct.unpack('!H', netsim.dns_answer(dns_query('x.test', 28), names, recorder, 'udp')[6:8])[0] == 0
    assert netsim.dns_answer(b'\x00' * 5, names, recorder, 'udp') is None


@pytest.mark.parametrize('host,path,expected', [
    ('api.ip.sb', '/ip', '203.0.113.24\n'), ('api.ipify.org', '/?format=json', '{"ip": "203.0.113.24"}'),
    ('www.msftconnecttest.com', '/connecttest.txt', 'Microsoft Connect Test')])
def test_http_responders(host, path, expected):
    assert netsim.http_response(host, 'GET', path, '203.0.113.24')[2] == expected


def test_http_responders_cover_exfiltration_channels_without_serving_binaries():
    status, _, body = netsim.http_response('api.telegram.org', 'POST', '/bot1:A/sendDocument', '203.0.113.24')
    assert status == 200 and json.loads(body)['ok'] is True
    assert netsim.http_response('discord.com', 'POST', '/api/webhooks/1/x', '1.2.3.4')[0] == 204
    assert netsim.http_response('cdn.example', 'GET', '/stage2.exe?x=1', '1.2.3.4')[0] == 404
    assert json.loads(netsim.http_response('ip-api.com', 'GET', '/json', '1.2.3.4')[2])['countryCode'] == 'US'


def test_persona_is_random_per_base_and_lists_canaries():
    first, second = generate(), generate()
    assert first['canaries']['marker'] != second['canaries']['marker']
    assert first['identity']['hostname'].startswith('DESKTOP-') and len(first['identity']['hostname']) == 15
    assert generate({'username': 'alex', 'hostname': 'FIN-PC01'})['identity']['username'] == 'alex'
    values = dict(canary_strings(first))
    assert values['discord_token'] == first['canaries']['discord_token']
    assert sum(kind.startswith('browser_password:') for kind in values) == len(first['canaries']['logins'])
    assert all(len(value) >= 8 for value in values.values())


def write_capture(tmp_path, events, blobs):
    (tmp_path / 'blobs').mkdir()
    for data in blobs:
        import hashlib
        (tmp_path / 'blobs' / hashlib.sha256(data).hexdigest()).write_bytes(data)
    (tmp_path / 'events.jsonl').write_text('\n'.join(json.dumps(e) for e in events) + '\n')


def body(data):
    import hashlib
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'stored': True}


def test_canary_scan_finds_values_inside_archives_encodings_and_credentials(tmp_path):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('Browsers/Chrome/Passwords.txt', 'URL: https://x\nPass: Kq9!secretA1\n')
    nested = gzip.compress(archive.getvalue())
    utf16 = 'token=dQw-canary-token-77'.encode('utf-16-le')
    b64 = base64.b64encode(b'seed: alpha bravo charlie delta')
    events = [{'seq': 1, 'kind': 'http', 'sni': 'api.telegram.org', 'target': '/bot1/sendDocument', 'body': body(nested)},
              {'seq': 2, 'kind': 'raw_stream', 'orig_ip': '198.18.1.9', 'orig_port': 1912, 'body': body(utf16)},
              {'seq': 3, 'kind': 'http', 'host': 'panel.test', 'body': body(b64)},
              {'seq': 4, 'kind': 'ftp_session', 'credentials': ['user', 'ftpPass!42']},
              {'seq': 5, 'kind': 'http', 'host': 'benign.test', 'body': {'sha256': '../../etc/passwd', 'stored': True}}]
    write_capture(tmp_path, events, [nested, utf16, b64])
    result = scan_netsim(tmp_path, [('browser_password:x', 'Kq9!secretA1'), ('discord_token', 'dQw-canary-token-77'),
                                    ('wallet_seed', 'alpha bravo charlie delta'), ('ftp_password', 'ftpPass!42'),
                                    ('absent', 'never-sent-value')])
    found = {(hit['canary'], hit['event_seq']) for hit in result['hits']}
    assert found == {('browser_password:x', 1), ('discord_token', 2), ('wallet_seed', 3), ('ftp_password', 4)}
    zipped = next(h for h in result['hits'] if h['event_seq'] == 1)
    assert zipped['container'] == 'body>gzip>zip:Browsers/Chrome/Passwords.txt' and zipped['destination'] == 'api.telegram.org'
    assert next(h for h in result['hits'] if h['event_seq'] == 2)['encoding'] == 'utf-16le'
    assert result['stolen_kinds'] == ['browser_password', 'discord_token', 'ftp_password', 'wallet_seed']


def test_canary_scan_without_capture_is_not_a_clean_result(tmp_path):
    assert scan_netsim(tmp_path, [('marker', 'abcdefghijkl')])['note'] == 'No network simulator capture'


SYSMON = """<Events>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1</EventID><TimeCreated SystemTime='2026-11-04T10:00:00Z'/></System>
<EventData><Data Name='UtcTime'>2026-11-04 10:00:00.100</Data><Data Name='ProcessGuid'>{A}</Data><Data Name='ProcessId'>4242</Data>
<Data Name='Image'>C:\\Users\\Sarah\\AppData\\Local\\Temp\\sample.bin.exe</Data><Data Name='ParentProcessGuid'>{P}</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1</EventID></System>
<EventData><Data Name='UtcTime'>2026-11-04 10:00:01.000</Data><Data Name='ProcessGuid'>{B}</Data><Data Name='ProcessId'>5000</Data>
<Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='CommandLine'>cmd /c whoami</Data><Data Name='ParentProcessGuid'>{A}</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>11</EventID></System>
<EventData><Data Name='UtcTime'>2026-11-04 10:00:02.000</Data><Data Name='ProcessGuid'>{B}</Data><Data Name='TargetFilename'>C:\\Users\\Sarah\\AppData\\Local\\Temp\\out.zip</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1</EventID></System>
<EventData><Data Name='UtcTime'>2026-11-04 10:00:03.000</Data><Data Name='ProcessGuid'>{X}</Data><Data Name='ProcessId'>7777</Data>
<Data Name='Image'>C:\\Windows\\System32\\svchost.exe</Data><Data Name='ParentProcessGuid'>{S}</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>3</EventID></System>
<EventData><Data Name='UtcTime'>2026-11-04 10:00:04.000</Data><Data Name='ProcessGuid'>{A}</Data><Data Name='DestinationIp'>198.18.1.7</Data><Data Name='DestinationPort'>443</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4</EventID></System><EventData/></Event>
</Events>"""


def test_lab_evidence_keeps_the_sample_process_tree_and_ranks_exfiltration(tmp_path):
    from core.lab_evidence import load
    sysmon = tmp_path / 'cape/analyses/1/sysmon'
    sysmon.mkdir(parents=True)
    (sysmon / 'sysmon.xml').write_text(SYSMON)
    (tmp_path / 'netsim').mkdir()
    (tmp_path / 'netsim/events.jsonl').write_text('\n'.join(json.dumps(e) for e in [
        {'seq': 1, 'kind': 'started'}, {'seq': 2, 'kind': 'dns', 'qname': 'www.msftconnecttest.com'},
        {'seq': 3, 'kind': 'http', 'host': 'panel.evil.top', 'method': 'POST', 'orig_ip': '198.18.1.7', 'orig_port': 443},
        {'seq': 5, 'kind': 'http', 'host': 'other.app.top', 'method': 'POST', 'orig_ip': '198.18.1.8', 'orig_port': 443},
        {'seq': 4, 'kind': 'http', 'host': 'www.bing.com', 'method': 'GET'}]))
    (tmp_path / 'canary_hits.json').write_text(json.dumps({'hits': [{'canary': 'discord_token', 'event_seq': 3}],
                                                           'stolen_kinds': ['discord_token']}))
    records, replay, summary = load(tmp_path, {'behavior': {'processes': [{'process_id': 4242}]}})
    assert [e['Image'] for e in replay if e['EventID'] == 1] == [
        'C:\\Users\\Sarah\\AppData\\Local\\Temp\\sample.bin.exe', 'C:\\Windows\\System32\\cmd.exe']
    assert any(e['EventID'] == 11 for e in replay) and summary['sysmon']['sample_tree_processes'] == 2
    priorities = {(kind, data.get('seq')): priority for kind, data, _, priority in records if kind.startswith('netsim_')}
    assert priorities[('netsim_http', 3)] == 0 and priorities[('netsim_http', 5)] == 2
    assert priorities[('netsim_http', 4)] == 4 and priorities[('netsim_dns', 2)] == 4
    assert summary['netsim']['sample_destinations'] == ['198.18.1.7:443']
    assert [priority for kind, *_, priority in records if kind == 'canary_hit'] == [0]


def test_replay_appendix_is_valid_for_ti2dac_event_extraction():
    import re
    from core.reporting import REPLAY_HEADING, with_replay_appendix
    events = [{'EventID': 1, 'Image': 'C:\\x\\a.exe', 'CommandLine': 'a.exe "x"'}]
    markdown = with_replay_appendix('# Report\n\nBody.', events)
    lines = re.findall(r'^\s*(\{.*\})\s*,?\s*$', markdown, re.M)   # ti2dac's embedded-event pattern
    assert [json.loads(line) for line in lines] == events
    assert markdown.count(REPLAY_HEADING) == 1 and with_replay_appendix(markdown, events) == markdown


def test_key_observations_lead_with_theft_exfiltration_and_dotnet_indicators(cape_report):
    from core.evidence import build_evidence
    from core.reporting import key_observations, readable_config
    lab = [('canary_hit', {'canary': 'browser_password:https://accounts.google.com/', 'destination': 'api.telegram.org',
                           'port': 443, 'event_kind': 'http', 'target': '/bot1/sendDocument', 'container': 'body>zip:p.txt'},
            'canary_hits.json#/hits/0', 0),
           ('netsim_http', {'kind': 'http', 'sni': 'api.telegram.org', 'orig_port': 443, 'method': 'POST',
                            'target': '/bot1/sendDocument', 'body': {'size': 2048}}, 'netsim/events.jsonl#5', 1),
           ('lab_summary', {'canaries': {'events_scanned': 9}, 'sysmon': {'status': 'absent'}}, 'managed lab', 0)]
    local = {'stages': [{'engine': 'dotnet_metadata', 'status': 'completed', 'input_sha256': 'a' * 64,
                         'result': {'status': 'completed', 'assembly': {'name': 'RuntimeHost'}, 'type_count': 2,
                                    'resources': [{'name': 'dll_b64.txt'}], 'user_strings': ['net.tcp://'],
                                    'pinvoke': [{'module': 'kernel32.dll', 'function': 'CreateRemoteThread'}]}}]}
    lines = '\n'.join(key_observations(build_evidence({}, [], cape_report, local_results=local, lab_records=lab)['records']))
    assert 'Planted canary data was sent out' in lines and 'api.telegram.org:443' in lines and 'body&gt;zip:p.txt' in lines
    assert 'POST /bot1/sendDocument' in lines and 'kernel32.dll!CreateRemoteThread' in lines and '`net.tcp://`' in lines
    assert readable_config({'RedLine': {'CNCs': ['127.0.0.1:1912'], 'botnet': ['test']}, '_associated_config_hashes': []}) \
        == 'RedLine: CNCs = 127.0.0.1:1912; botnet = test'


def test_sysmon_replay_events_exclude_cape_harness_activity():
    from core.lab_evidence import in_tree
    tree = {'{S}'}
    assert in_tree({'EventID': 11, 'ProcessGuid': '{S}', 'TargetFilename': 'C:\\Users\\a\\x.zip'}, tree)
    assert not in_tree({'EventID': 11, 'ProcessGuid': '{S}', 'TargetFilename': 'C:\\WCUVUVgOR\\CAPE\\out.bin'}, tree)
    assert not in_tree({'EventID': 18, 'ProcessGuid': '{S}', 'PipeName': '\\ajXdyKz'}, tree, {'ajXdyKz'})
    assert in_tree({'EventID': 18, 'ProcessGuid': '{S}', 'PipeName': '\\evilpipe'}, tree, {'ajXdyKz'})
    assert not in_tree({'EventID': 12, 'ProcessGuid': '{S}', 'EventType': 'CreateKey'}, tree)
    assert in_tree({'EventID': 13, 'ProcessGuid': '{S}', 'EventType': 'SetValue'}, tree)
    assert not in_tree({'EventID': 1, 'ProcessGuid': '{X}'}, tree)


def test_victim_data_access_groups_file_calls_on_planted_locations():
    from core.reporting import victim_data_access
    def rec(i, api, name):
        return {'id': f'E{i:07d}', 'data': {'api': api, 'arguments': {'FileName': name}}}
    base = 'C:\\Users\\Jessica\\AppData\\'
    found = victim_data_access([
        rec(1, 'NtQueryFullAttributesFile', base + 'Local\\Google\\Chrome\\User Data\\Default\\Login Data'),
        rec(2, 'NtCreateFile', base + 'Local\\Google\\Chrome\\User Data\\Default\\Login Data'),
        rec(3, 'FindFirstFileExW', base + 'Roaming\\Telegram Desktop\\tdata\\*'),
        rec(4, 'NtCreateFile', base + 'Local\\Temp\\other.txt'),
        rec(5, 'RegOpenKeyExW', base + 'Roaming\\Electrum\\wallets')])
    assert found == {'Chromium passwords/cards (Login Data, Web Data)': ('E0000001', 2),
                     'Telegram session (tdata)': ('E0000003', 1)}


def test_victim_data_access_ignores_write_only_opens():
    """RedLine f7856dc0 appends to its author's log under C:\\Users\\artem\\Documents; that is not document theft."""
    from core.reporting import victim_data_access
    def rec(i, access):
        arguments = {'FileName': 'C:\\Users\\artem\\Documents\\vbiv\\scripts\\secure_sender_log.txt'}
        if access is not None:
            arguments['DesiredAccess'] = access
        return {'id': f'E{i:07d}', 'data': {'api': 'NtCreateFile', 'arguments': arguments}}
    assert victim_data_access([rec(1, '0x40100080')]) == {}
    assert victim_data_access([rec(1, '0x40100080'), rec(2, '0x80100080'), rec(3, None)]) == {
        'User documents': ('E0000002', 2)}


def test_line_c2_replays_its_script_once_and_counts_keepalives(monkeypatch):
    import threading
    monkeypatch.setattr(netsim, 'LINE_C2_SCRIPT', ((0, 'tls https://a.example/ 1', 0.2), (0, 'stop https://a.example/', 0.2)))
    monkeypatch.setattr(netsim, 'LINE_C2_SESSIONS', __import__('itertools').count(1))
    recorder = Memory()
    for session in (1, 2):
        server, bot = socket.socketpair()
        bot.sendall(b'REGISTER windows 386\n')
        first = server.recv(8)
        info = {'orig_ip': '176.65.139.76', 'orig_port': 9111}
        worker = threading.Thread(target=netsim.handle_line_c2, args=(server, first, {'recorder': recorder, 'conn_info': info}))
        worker.start()
        bot.settimeout(2)
        commands = bot.recv(4096) if session == 1 else b''
        while session == 1 and commands.count(b'\n') < 2:
            commands += bot.recv(4096)
        bot.sendall(b'\n\n')
        bot.close()
        worker.join(5)
        if session == 1:
            assert commands == b'tls https://a.example/ 1\nstop https://a.example/\n'
    kinds = [e['kind'] for e in recorder.events]
    assert kinds.count('c2_command') == 2 and kinds.count('c2_session') == 2
    ends = [e for e in recorder.events if e['kind'] == 'c2_session_end']
    assert ends[0]['keepalives'] == 2 and ends[0]['closed_by_client'] and ends[1]['keepalives'] == 2


def test_http_floods_are_counted_after_the_record_limit_and_cf_hosts_challenge(monkeypatch):
    monkeypatch.setattr(netsim, 'HTTP_RECORD_LIMIT', 2)
    monkeypatch.setattr(netsim, 'HTTP_RECORDED', {})
    server, client = socket.socketpair()
    request = b'GET / HTTP/1.1\r\nHost: cf-x.example\r\n\r\n'
    client.sendall(request + request.replace(b'\r\n\r\n', b'\r\nCookie: ' + netsim.CF_CLEARANCE.encode() + b'\r\n\r\n') + request * 2)
    client.shutdown(socket.SHUT_WR)
    recorder = Memory()
    netsim.handle_http(server, b'', {'recorder': recorder, 'host': 'cf-x.example', 'public_ip': '1.2.3.4', 'conn_info': {}})
    replies = client.recv(65536).decode()
    assert replies.count('503 Service Unavailable') == 3 and replies.count('200 OK') == 1
    assert 'Set-Cookie: cf_clearance=' in replies and 'Server: cloudflare' in replies
    assert [e['status'] for e in recorder.events if e['kind'] == 'http'] == [503, 200]
    assert [e['requests'] for e in recorder.events if e['kind'] == 'http_suppressed'] == [2]
