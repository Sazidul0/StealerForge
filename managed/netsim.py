"""Simulated internet for one analysis: fake DNS, transparent TCP sink, TLS interception and service responders.

Runs inside the run's sealed network namespace. iptables (netsetup.sh) redirects every outbound TCP connection
and DNS query here; nothing is forwarded anywhere, so samples see "internet" without reaching it. Every request
is written to <out>/events.jsonl, with bodies and raw streams under <out>/blobs/ (size-capped).
"""
import argparse
import base64
import datetime
import hashlib
import ipaddress
import itertools
import json
import os
from pathlib import Path
import queue
import socket
import ssl
import struct
import tempfile
import threading
import time
from urllib.parse import urlsplit

SO_ORIGINAL_DST = 80
SINK_POOL = ipaddress.ip_network('198.18.0.0/15')   # benchmarking range: never routed on the internet
NCSI = {'dns.msftncsi.com': '131.107.255.255'}       # Windows connectivity check expects this exact answer
MAX_BODY = 64 * 1024 * 1024
BINARY_SUFFIXES = ('.exe', '.dll', '.scr', '.msi', '.ps1', '.bat', '.vbs', '.js', '.hta', '.bin', '.dat', '.zip', '.rar', '.7z',
                   '.cab')


class Recorder:
    def __init__(self, out, budget):
        self.out = Path(out)
        (self.out / 'blobs').mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.budget = budget
        self.used = 0
        self.sequence = 0

    def event(self, kind, **values):
        with self.lock:
            self.sequence += 1
            record = {'seq': self.sequence, 'time': time.time(), 'kind': kind, **values}
            with (self.out / 'events.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(record, ensure_ascii=True) + '\n')
        return record

    def blob(self, data):
        if not data:
            return None
        digest = hashlib.sha256(data).hexdigest()
        with self.lock:
            path = self.out / 'blobs' / digest
            if not path.exists():
                if self.used + len(data) > self.budget:
                    return {'sha256': digest, 'size': len(data), 'stored': False}
                path.write_bytes(data)
                self.used += len(data)
        return {'sha256': digest, 'size': len(data), 'stored': True}


class Names:
    """Stable fake addresses per DNS name, so a connection's original destination maps back to its name."""
    def __init__(self):
        self.lock = threading.Lock()
        self.by_name, self.by_ip = {}, {}
        self.next = int(SINK_POOL.network_address) + 256

    def resolve(self, name):
        name = name.rstrip('.').lower()
        if name in NCSI:
            return NCSI[name]
        with self.lock:
            if name not in self.by_name:
                address = str(ipaddress.ip_address(self.next))
                self.next += 1
                self.by_name[name], self.by_ip[address] = address, name
            return self.by_name[name]

    def name_for(self, address):
        with self.lock:
            return self.by_ip.get(address)


# ------------------------------------------------------------------------------------------------------- DNS
def parse_query(packet):
    if len(packet) < 12:
        raise ValueError('short DNS packet')
    labels, offset = [], 12
    while True:
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            raise ValueError('compressed name in question')
        labels.append(packet[offset + 1:offset + 1 + length].decode('ascii', 'replace'))
        offset += 1 + length
    qtype, qclass = struct.unpack('!HH', packet[offset:offset + 4])
    return '.'.join(labels), qtype, qclass, packet[12:offset + 4]


def dns_answer(packet, names, recorder, source):
    try:
        name, qtype, qclass, question = parse_query(packet)
    except (ValueError, IndexError, struct.error):
        return None
    flags = 0x8180 | (packet[2] & 0x01) << 8  # response, recursion available, copy RD
    answers = b''
    address = None
    if qtype == 1 and qclass == 1:
        address = names.resolve(name)
        answers = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(address)
    recorder.event('dns', qname=name, qtype=qtype, answer=address, source=source)
    header = packet[:2] + struct.pack('!HHHHH', flags, 1, 1 if answers else 0, 0, 0)
    return header + question + answers


def serve_dns_udp(port, names, recorder):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', port))
    while True:
        packet, peer = sock.recvfrom(4096)
        reply = dns_answer(packet, names, recorder, 'udp')
        if reply:
            sock.sendto(reply, peer)


# ------------------------------------------------------------------------------------------------------- TLS
class Certificates:
    def __init__(self, ca_dir):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        self.x509 = x509
        ca_dir = Path(ca_dir)
        self.ca_cert = x509.load_pem_x509_certificate((ca_dir / 'ca.crt').read_bytes())
        self.ca_key = serialization.load_pem_private_key((ca_dir / 'ca.key').read_bytes(), password=None)
        self.cache = {}
        self.lock = threading.Lock()
        self.work = Path(tempfile.mkdtemp(prefix='netsim-certs-'))

    @staticmethod
    def _new_context(path):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.set_ciphers('DEFAULT:@SECLEVEL=0')
        context.set_alpn_protocols(['http/1.1'])
        context.load_cert_chain(path)
        return context

    def pem(self, name):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        x509 = self.x509
        with self.lock:
            if name in self.cache:
                return self.cache[name]
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            try:
                alt = x509.IPAddress(ipaddress.ip_address(name))
            except ValueError:
                alt = x509.DNSName(name)
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name[:64])]))
                    .issuer_name(self.ca_cert.subject).public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=2)).not_valid_after(now + datetime.timedelta(days=300))
                    .add_extension(x509.SubjectAlternativeName([alt]), critical=False)
                    .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                    .sign(self.ca_key, hashes.SHA256()))
            path = self.work / (hashlib.sha256(name.encode()).hexdigest()[:24] + '.pem')
            # Leaf key, leaf certificate and the CA, as load_cert_chain expects.
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption())
                             + cert.public_bytes(serialization.Encoding.PEM)
                             + self.ca_cert.public_bytes(serialization.Encoding.PEM))
            self.cache[name] = (path, self._new_context(path))
            return self.cache[name]

    def wrap(self, conn, fallback_name):
        chosen = {}

        def pick(sslobj, server_name, _context):
            chosen['sni'] = server_name
            if server_name:
                sslobj.context = self.pem(server_name)[1]

        # A fresh base context per connection: the SNI callback must not be shared between threads.
        base = self._new_context(self.pem(fallback_name)[0])
        base.sni_callback = pick
        tls = base.wrap_socket(conn, server_side=True)
        return tls, chosen.get('sni')


def make_ca(directory, organization):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                      x509.NameAttribute(NameOID.COMMON_NAME, f'{organization} Root CA')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=400))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    key_path = directory / 'ca.key'
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    key_path.chmod(0o600)
    (directory / 'ca.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))


# ------------------------------------------------------------------------------------------------- responders
def fake_geo(ip):
    return {'ip': ip, 'city': 'Boston', 'region': 'Massachusetts', 'region_code': 'MA', 'country': 'US',
            'country_name': 'United States', 'country_code': 'US', 'postal': '02108', 'latitude': 42.3584,
            'longitude': -71.0598, 'timezone': 'America/New_York', 'org': 'AS7922 Comcast Cable Communications, LLC'}


def http_response(host, method, path, public_ip):
    """(status, content_type, body) for a request. Only canned data: nothing is fetched or executed."""
    host = (host or '').split(':')[0].lower()
    geo = fake_geo(public_ip)
    if host in ('api.ipify.org', 'api64.ipify.org', 'icanhazip.com', 'ipv4.icanhazip.com', 'ifconfig.me',
                'checkip.amazonaws.com', 'wtfismyip.com', 'myexternalip.com', 'ident.me', 'ipecho.net'):
        if 'format=json' in path:
            return 200, 'application/json', json.dumps({'ip': public_ip})
        return 200, 'text/plain', public_ip + '\n'
    if host == 'api.ip.sb':
        return (200, 'text/plain', public_ip + '\n') if path.startswith('/ip') else (200, 'application/json', json.dumps(geo))
    if host in ('ip-api.com', 'pro.ip-api.com'):
        return 200, 'application/json', json.dumps({'status': 'success', 'country': 'United States', 'countryCode': 'US',
                                                   'region': 'MA', 'regionName': 'Massachusetts', 'city': 'Boston',
                                                   'zip': '02108', 'lat': 42.3584, 'lon': -71.0598,
                                                   'timezone': 'America/New_York', 'isp': 'Comcast Cable',
                                                   'org': 'Comcast Cable', 'as': 'AS7922 Comcast Cable', 'query': public_ip})
    if host in ('ipinfo.io', 'ipapi.co', 'freegeoip.app', 'geolocation-db.com', 'api.myip.com', 'ipwho.is',
                'ipwhois.app', 'get.geojs.io', 'extreme-ip-lookup.com'):
        if host == 'ipapi.co' and path.rstrip('/').endswith('/ip'):
            return 200, 'text/plain', public_ip
        return 200, 'application/json', json.dumps(dict(geo, success=True, cc='US', country_code2='US'))
    if host == 'api.telegram.org':
        result = ({'id': 7000000001, 'is_bot': True, 'first_name': 'assistant', 'username': 'assistant_bot'}
                  if path.endswith('/getMe') else {'message_id': 1, 'date': int(time.time()), 'chat': {'id': 1, 'type': 'private'}})
        return 200, 'application/json', json.dumps({'ok': True, 'result': result})
    if host.endswith(('discord.com', 'discordapp.com')) and '/api/webhooks/' in path:
        return 204, 'text/plain', ''
    if host == 'www.msftconnecttest.com':
        return 200, 'text/plain', 'Microsoft Connect Test'
    if host == 'www.msftncsi.com':
        return 200, 'text/plain', 'Microsoft NCSI'
    if path.endswith('/generate_204'):
        return 204, 'text/plain', ''
    if method == 'GET' and urlsplit(path).path.lower().endswith(BINARY_SUFFIXES):
        return 404, 'text/html', '<html><body><h1>404 Not Found</h1></body></html>'
    if method in ('POST', 'PUT'):
        return 200, 'application/json', '{"status":"ok"}'
    return 200, 'text/html', '<html><head><title>OK</title></head><body>OK</body></html>'


def read_line(conn, limit=65536):
    data = bytearray()
    while not data.endswith(b'\n'):
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise ValueError('line too long')
    return bytes(data)


def read_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(min(65536, size - len(data)))
        if not chunk:
            break
        data += chunk
    return bytes(data)


def handle_http(conn, first, ctx):
    """HTTP/1.1 with keep-alive. `first` holds bytes already consumed while sniffing the protocol."""
    buffer = bytearray(first)
    conn.settimeout(10)   # idle keep-alive connections must not hold one of the simulator's slots for long

    def line():
        nonlocal buffer
        while b'\n' not in buffer:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            buffer += chunk
            if len(buffer) > 65536:
                raise ValueError('header too long')
        index = buffer.index(b'\n') + 1
        value, buffer = bytes(buffer[:index]), buffer[index:]
        return value

    def body(size):
        nonlocal buffer
        while len(buffer) < size:
            chunk = conn.recv(min(65536, size - len(buffer)))
            if not chunk:
                break
            buffer += chunk
        value, buffer = bytes(buffer[:size]), buffer[size:]
        return value

    suppressed = 0
    try:
        while True:
            request = serve_http_request(conn, ctx, line, body)
            if request is None:
                return
            suppressed += request == 'suppressed'
    finally:
        if suppressed:
            ctx['recorder'].event('http_suppressed', **ctx['conn_info'], host=ctx['host'], requests=suppressed)


# Floods repeat one request thousands of times: record the first ones per host, then only count them.
HTTP_RECORD_LIMIT = 40
HTTP_RECORDED = {}
HTTP_RECORDED_LOCK = threading.Lock()


def serve_http_request(conn, ctx, line, body):
    """Answer one request; returns None when the client is done, 'suppressed' when it was only counted."""
    request_line = line()
    if not request_line or not request_line.strip():
        return None
    parts = request_line.decode('latin-1').strip().split(' ')
    method, target = parts[0], parts[1] if len(parts) > 1 else '/'
    headers = {}
    while (header := line()) and header.strip():
        name, _, value = header.decode('latin-1').partition(':')
        headers[name.strip().lower()] = value.strip()
    if headers.get('transfer-encoding', '').lower() == 'chunked':
        data = bytearray()
        while (size_line := line()) is not None:
            size = int(size_line.split(b';')[0].strip() or b'0', 16)
            if size == 0:
                line()
                break
            data += body(size)
            line()
            if len(data) > MAX_BODY:
                raise ValueError('body too large')
        payload = bytes(data)
    else:
        payload = body(min(int(headers.get('content-length', '0') or 0), MAX_BODY))
    host = headers.get('host') or ctx['host']
    status, content_type, reply = http_response(host, method, target, ctx['public_ip'])
    extra = ''
    if cf_challenge_host(host) and CF_CLEARANCE not in headers.get('cookie', ''):
        status, content_type, reply = 503, 'text/html', '<html><title>Just a moment...</title><body>Checking your browser</body></html>'
        extra = f'Set-Cookie: {CF_CLEARANCE}; Path=/; HttpOnly\r\nCF-RAY: 0000000000000000-BOS\r\n'
    with HTTP_RECORDED_LOCK:
        seen = HTTP_RECORDED[host.lower()] = HTTP_RECORDED.get(host.lower(), 0) + 1
    recorded = bool(payload) or seen <= HTTP_RECORD_LIMIT   # bodies are always kept: they may be exfiltration
    if recorded:
        ctx['recorder'].event('http', **ctx['conn_info'], method=method, host=host, target=target,
                              headers=dict(list(headers.items())[:40]), body=ctx['recorder'].blob(payload),
                              status=status)
    data = reply.encode()
    server = 'cloudflare' if cf_challenge_host(host) else 'nginx'
    reason = {503: 'Service Unavailable'}.get(status, 'OK' if status < 300 else 'Not Found')
    conn.sendall(f'HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n{extra}'
                 f'Content-Length: {len(data)}\r\nServer: {server}\r\nConnection: keep-alive\r\n\r\n'.encode() + data)
    if headers.get('connection', '').lower() == 'close':
        return None
    return 'recorded' if recorded else 'suppressed'


# Hosts named cf-*.example answer like a Cloudflare challenge until the client returns the clearance cookie.
CF_CLEARANCE = 'cf_clearance=stealerforge-lab-clearance'


def cf_challenge_host(host):
    host = (host or '').split(':')[0].lower()
    return host.startswith('cf-') and host.endswith('.example')


def handle_smtp(conn, ctx, implicit_tls):
    recorder = ctx['recorder']
    conn.sendall(b'220 mail.example.com ESMTP Postfix\r\n')
    commands, auth = [], []
    while True:
        raw = read_line(conn)
        if not raw:
            break
        text = raw.decode('latin-1').strip()
        verb = text.split(' ')[0].upper()
        commands.append(text[:500])
        if verb in ('EHLO', 'HELO'):
            conn.sendall(b'250-mail.example.com\r\n250-AUTH LOGIN PLAIN\r\n' + (b'' if implicit_tls else b'250-STARTTLS\r\n')
                         + b'250 8BITMIME\r\n')
        elif verb == 'STARTTLS':
            conn.sendall(b'220 Ready to start TLS\r\n')
            conn, _ = ctx['certs'].wrap(conn, ctx['host'])
            implicit_tls = True
        elif verb == 'AUTH':
            parts = text.split(' ')
            if len(parts) > 2:
                auth.append(parts[2])
            elif parts[1:] and parts[1].upper() == 'LOGIN':
                for prompt in (b'334 VXNlcm5hbWU6\r\n', b'334 UGFzc3dvcmQ6\r\n'):
                    conn.sendall(prompt)
                    auth.append(read_line(conn).decode('latin-1').strip())
            elif parts[1:] and parts[1].upper() == 'PLAIN':
                conn.sendall(b'334 \r\n')
                auth.append(read_line(conn).decode('latin-1').strip())
            conn.sendall(b'235 2.7.0 Authentication successful\r\n')
        elif verb == 'DATA':
            conn.sendall(b'354 End data with <CR><LF>.<CR><LF>\r\n')
            message = bytearray()
            while (chunk := read_line(conn, 1 << 20)) and chunk.rstrip(b'\r\n') != b'.':
                message += chunk
                if len(message) > MAX_BODY:
                    break
            recorder.event('smtp_message', **ctx['conn_info'], body=recorder.blob(bytes(message)))
            conn.sendall(b'250 2.0.0 Ok: queued\r\n')
        elif verb == 'QUIT':
            conn.sendall(b'221 2.0.0 Bye\r\n')
            break
        else:
            conn.sendall(b'250 2.0.0 Ok\r\n')
    decoded = []
    for item in auth:
        try:
            decoded.append(base64.b64decode(item, validate=True).decode('utf-8', 'replace'))
        except ValueError:
            decoded.append(item)
    recorder.event('smtp_session', **ctx['conn_info'], commands=commands[:200], auth=decoded)


PASSIVE = {}
PASSIVE_LOCK = threading.Lock()
PASSIVE_PORTS = itertools.cycle(range(40000, 60000))


def handle_ftp(conn, ctx):
    recorder = ctx['recorder']
    conn.sendall(b'220 (vsFTPd 3.0.5)\r\n')
    commands, credentials = [], []
    channel = None
    while True:
        raw = read_line(conn)
        if not raw:
            break
        text = raw.decode('latin-1').strip()
        verb, _, argument = text.partition(' ')
        verb = verb.upper()
        commands.append(text[:500])
        if verb == 'USER':
            credentials.append(argument)
            conn.sendall(b'331 Please specify the password.\r\n')
        elif verb == 'PASS':
            credentials.append(argument)
            conn.sendall(b'230 Login successful.\r\n')
        elif verb in ('PASV', 'EPSV'):
            with PASSIVE_LOCK:
                data_port = next(port for port in PASSIVE_PORTS if port not in PASSIVE)
                channel = PASSIVE[data_port] = queue.Queue(1)
            address = ctx['conn_info']['orig_ip']
            if verb == 'EPSV':
                conn.sendall(f'229 Entering Extended Passive Mode (|||{data_port}|)\r\n'.encode())
            else:
                octets = address.replace('.', ',')
                conn.sendall(f'227 Entering Passive Mode ({octets},{data_port >> 8},{data_port & 255}).\r\n'.encode())
        elif verb in ('STOR', 'APPE', 'LIST', 'NLST', 'RETR'):
            conn.sendall(b'150 Ok to send data.\r\n')
            try:
                data_conn = channel.get(timeout=20) if channel else None
            except queue.Empty:
                data_conn = None
            payload = b''
            if data_conn is not None:
                if verb in ('STOR', 'APPE'):
                    data_conn.settimeout(30)
                    payload = read_exact(data_conn, MAX_BODY)
                data_conn.close()
            if verb in ('STOR', 'APPE'):
                recorder.event('ftp_upload', **ctx['conn_info'], filename=argument[:300], body=recorder.blob(payload))
            conn.sendall(b'226 Transfer complete.\r\n')
        elif verb == 'QUIT':
            conn.sendall(b'221 Goodbye.\r\n')
            break
        else:
            reply = {'SYST': '215 UNIX Type: L8', 'PWD': '257 "/" is the current directory', 'TYPE': '200 Switching mode.',
                     'CWD': '250 Directory successfully changed.', 'MKD': '257 Created', 'FEAT': '211 End',
                     'OPTS': '200 OK', 'NOOP': '200 NOOP ok.', 'SIZE': '550 Could not get file size.'}.get(verb, '200 OK')
            conn.sendall(reply.encode() + b'\r\n')
    recorder.event('ftp_session', **ctx['conn_info'], commands=commands[:200], credentials=credentials[:10])


# Plain-text DDoS-bot C2 ("REGISTER <os> <arch>", then one command per line, e.g. the Go apex2 bot).
# Every target is a documentation address or a .example name: TCP floods land back in this simulator
# and UDP floods die on the sealed sink device, where only the guest packet capture sees them.
LINE_C2_SCRIPT = (
    (5, 'udp 198.51.100.20 80 3', 3),
    (0, 'game 198.51.100.21 27015 4', 7),
    (0, 'discord 198.51.100.22 50001 4', 7),
    # TCP floods hold every simulator slot until their keep-alive connections idle out (30 s): space them.
    (0, 'cf https://cf-flood.lab-target.example/ 15', 40),
    (0, 'tlsplus https://tlsplus-flood.lab-target.example/index.php 8', 40),
    (0, 'tlsplusbypass https://bypass-flood.lab-target.example/ 8', 40),
    (0, 'tls https://tls-flood.lab-target.example/ 8', 40),
    (0, 'tls https://stop-test.lab-target.example/ 120', 6),
    (0, 'stop https://stop-test.lab-target.example/', 10),
    # Last: pps only checks for cancellation every 10,000 packets per worker and saturates the guest NIC.
    (0, 'pps 198.51.100.23 9987 4', 7),
)
LINE_C2_SESSIONS = itertools.count(1)


def handle_line_c2(conn, first, ctx):
    """Replay the command script once (later reconnects are only recorded) and log what the bot sends."""
    recorder, info = ctx['recorder'], ctx['conn_info']
    session = next(LINE_C2_SESSIONS)
    received = bytearray(first)
    try:
        received += conn.recv(256)
    except (socket.timeout, OSError):
        pass
    hello = bytes(received).split(b'\n')[0].decode('latin-1')
    recorder.event('c2_session', **info, session=session, protocol='line', register=hello)
    received = received[len(hello) + 1:]
    keepalives = 0

    def drain(seconds):
        nonlocal received, keepalives
        deadline = time.monotonic() + seconds
        while (left := deadline - time.monotonic()) > 0:
            conn.settimeout(left)
            try:
                chunk = conn.recv(4096)
            except (socket.timeout, TimeoutError):
                return True
            if not chunk:
                return False
            keepalives += chunk.count(b'\n') if not chunk.strip() else 0
            if chunk.strip():
                received += chunk
        return True

    alive = True
    for before, command, after in (LINE_C2_SCRIPT if session == 1 else ()):
        if not (alive := drain(before)):
            break
        conn.sendall(command.encode() + b'\n')
        recorder.event('c2_command', **info, session=session, command=command)
        if not (alive := drain(after)):
            break
    while alive and keepalives < 10000:   # the guest may be torn down mid-session: report progress as we go
        alive = drain(60)
        recorder.event('c2_keepalives', **info, session=session, keepalives=keepalives)
    recorder.event('c2_session_end', **info, session=session, keepalives=keepalives, closed_by_client=not alive,
                   other_data=recorder.blob(bytes(received)))


def handle_connection(conn, peer, settings):
    recorder, names, certs = settings['recorder'], settings['names'], settings['certs']
    try:
        raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port, packed = struct.unpack('!2xH4s8x', raw)
        orig_ip = socket.inet_ntoa(packed)
    except OSError:
        orig_ip, port = '0.0.0.0', 0
    with PASSIVE_LOCK:
        channel = PASSIVE.pop(port, None)
    if channel is not None:
        channel.put(conn)   # an FTP data connection; the control session owns and closes it
        return
    host = names.name_for(orig_ip) or orig_ip
    info = {'orig_ip': orig_ip, 'orig_port': port, 'name': names.name_for(orig_ip)}
    ctx = {'recorder': recorder, 'certs': certs, 'host': host, 'public_ip': settings['public_ip'], 'conn_info': info}
    record = recorder.event('tcp_connect', **info)
    info['connection'] = record['seq']
    conn.settimeout(30)
    try:
        if port in (25, 587, 2525):
            return handle_smtp(conn, ctx, False)
        if port == 21:
            return handle_ftp(conn, ctx)
        if port == 53:
            size = struct.unpack('!H', read_exact(conn, 2))[0]
            reply = dns_answer(read_exact(conn, size), names, recorder, 'tcp')
            if reply:
                conn.sendall(struct.pack('!H', len(reply)) + reply)
            return
        conn.settimeout(5)
        try:
            first = conn.recv(8, socket.MSG_PEEK)
        except socket.timeout:
            first = b''
        conn.settimeout(30)
        if first[:1] == b'\x16':
            try:
                conn, sni = certs.wrap(conn, host)
            except (ssl.SSLError, OSError) as exc:
                recorder.event('tls_failed', **info, error=str(exc)[:300])
                return
            info['sni'] = sni
            ctx['host'] = sni or host
            recorder.event('tls', **info, version=conn.version(), cipher=(conn.cipher() or [None])[0])
            if port == 465:
                return handle_smtp(conn, ctx, True)
            conn.settimeout(5)
            try:
                first = conn.recv(8)
            except (socket.timeout, ssl.SSLError):
                first = b''
            conn.settimeout(30)
        else:
            first = conn.recv(8) if first else b''
        token = first.split(b' ')[0]
        if token in (b'GET', b'POST', b'PUT', b'HEAD', b'DELETE', b'OPTIONS', b'PATCH', b'CONNECT'):
            return handle_http(conn, first, ctx)
        if first.startswith(b'REGISTER'):
            return handle_line_c2(conn, first, ctx)
        if not first:   # silent for 5 s (often a flood worker that already gave up): free the slot
            recorder.event('raw_stream', **info, body=None)
            return
        # Unknown protocol: keep the connection open and record what the client sends.
        data = bytearray(first)
        conn.settimeout(15)
        try:
            while len(data) < 16 * 1024 * 1024 and (chunk := conn.recv(65536)):
                data += chunk
        except (socket.timeout, ssl.SSLError, OSError):
            pass
        recorder.event('raw_stream', **info, body=recorder.blob(bytes(data)))
    except (socket.timeout, TimeoutError):
        pass  # an idle keep-alive connection, not an error
    except Exception as exc:  # one malformed client must never stop the simulator
        recorder.event('handler_error', **info, error=f'{type(exc).__name__}: {str(exc)[:300]}')
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(args):
    recorder = Recorder(args.out, args.budget_mb * 1024 * 1024)
    names = Names()
    settings = {'recorder': recorder, 'names': names, 'certs': Certificates(args.ca), 'public_ip': args.public_ip}
    threading.Thread(target=serve_dns_udp, args=(args.dns_port, names, recorder), daemon=True).start()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', args.tcp_port))
    listener.listen(256)
    slots = threading.BoundedSemaphore(128)
    recorder.event('started', dns_port=args.dns_port, tcp_port=args.tcp_port, public_ip=args.public_ip)

    def worker(conn, peer):
        try:
            handle_connection(conn, peer, settings)
        finally:
            slots.release()

    while True:
        conn, peer = listener.accept()
        if not slots.acquire(timeout=5):
            conn.close()
            continue
        threading.Thread(target=worker, args=(conn, peer), daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    ca = commands.add_parser('make-ca')
    ca.add_argument('directory')
    ca.add_argument('--organization', required=True)
    run = commands.add_parser('serve')
    run.add_argument('--ca', required=True)
    run.add_argument('--out', required=True)
    run.add_argument('--public-ip', default='203.0.113.24')
    run.add_argument('--dns-port', type=int, default=15053)
    run.add_argument('--tcp-port', type=int, default=15080)
    run.add_argument('--budget-mb', type=int, default=512)
    args = parser.parse_args()
    if args.command == 'make-ca':
        make_ca(args.directory, args.organization)
    else:
        os.umask(0o022)
        serve(args)


if __name__ == '__main__':
    main()
