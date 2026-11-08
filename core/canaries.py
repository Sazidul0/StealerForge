"""Find planted canary values in simulated-internet captures: direct proof of what a sample stole and sent.

Captured bodies are attacker-controlled bytes. They are only decompressed (gzip, zlib, ZIP) and base64-decoded,
within fixed size, member and depth limits, and searched for exact canary byte strings.
"""
import base64
import binascii
import gzip
import io
import json
from pathlib import Path
import re
import zipfile
import zlib
from urllib.parse import quote, quote_plus

MAX_LAYER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 500
MAX_DEPTH = 3
MAX_EVENTS = 200000
BASE64_TEXT = re.compile(rb'[A-Za-z0-9+/=\r\n_-]{24,}')


def variants(value):
    forms = {'utf-8': value.encode(), 'utf-16le': value.encode('utf-16-le'), 'url': quote(value).encode(),
             'url-plus': quote_plus(value).encode(), 'json': json.dumps(value)[1:-1].encode(),
             'base64': base64.b64encode(value.encode())}
    return [(name, needle) for name, needle in forms.items() if len(needle) >= 6]


class Budget:
    def __init__(self):
        self.used = 0

    def take(self, size):
        self.used += size
        return self.used <= MAX_TOTAL_BYTES


def _bounded(stream):
    data = stream.read(MAX_LAYER_BYTES + 1)
    return data[:MAX_LAYER_BYTES]


def layers(data, budget, path='body', depth=0):
    """Yield (container path, bytes) for the data and anything decompressed or decoded from it."""
    yield path, data
    if depth >= MAX_DEPTH or not budget.take(len(data)):
        return
    children = []
    try:
        if data[:2] == b'\x1f\x8b':
            children.append((path + '>gzip', _bounded(gzip.GzipFile(fileobj=io.BytesIO(data)))))
        elif data[:1] == b'\x78':
            children.append((path + '>zlib', zlib.decompressobj().decompress(data, MAX_LAYER_BYTES)))
    except (OSError, EOFError, zlib.error):
        pass
    if data[:4] == b'PK\x03\x04':
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist()[:MAX_MEMBERS]:
                    if info.is_dir() or info.file_size > MAX_LAYER_BYTES:
                        continue
                    try:
                        with archive.open(info) as member:
                            children.append((f'{path}>zip:{info.filename[:200]}', _bounded(member)))
                    except (RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error):
                        children.append((f'{path}>zip:{info.filename[:200]} (encrypted or unsupported)', b''))
        except zipfile.BadZipFile:
            pass
    stripped = data.strip()
    if len(stripped) >= 24 and BASE64_TEXT.fullmatch(stripped):
        compact = re.sub(rb'\s+', b'', stripped)
        try:
            decoded = (base64.urlsafe_b64decode if b'-' in compact or b'_' in compact else base64.b64decode)(
                compact + b'=' * (-len(compact) % 4))
            children.append((path + '>base64', decoded))
        except (binascii.Error, ValueError):
            pass
    for child_path, child in children:
        if child:
            yield from layers(child, budget, child_path, depth + 1)


def scan_netsim(directory, canaries):
    directory = Path(directory)
    events_file = directory / 'events.jsonl'
    result = {'hits': [], 'events_scanned': 0, 'blobs_scanned': 0, 'canaries': len(canaries),
              'limits': {'layer_bytes': MAX_LAYER_BYTES, 'total_bytes': MAX_TOTAL_BYTES, 'depth': MAX_DEPTH}}
    if not events_file.is_file():
        result['note'] = 'No network simulator capture'
        return result
    needles = [(kind, value, encoding, needle) for kind, value in canaries for encoding, needle in variants(value)]
    budget, seen = Budget(), set()
    with events_file.open(encoding='utf-8', errors='replace') as stream:
        for index, line in enumerate(stream):
            if index >= MAX_EVENTS:
                result['note'] = 'Event limit reached; later events were not scanned'
                break
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            result['events_scanned'] += 1
            sources = []
            # Credentials typed into SMTP AUTH / FTP USER-PASS and the request line itself are also exfiltration.
            text = json.dumps({k: event.get(k) for k in ('auth', 'credentials', 'commands', 'target', 'headers', 'filename')
                               if event.get(k)}, ensure_ascii=False)
            if text != '{}':
                sources.append(('metadata', text.encode()))
            body = event.get('body') or {}
            blob = directory / 'blobs' / str(body.get('sha256', ''))
            if body.get('stored') and re.fullmatch(r'[0-9a-f]{64}', str(body.get('sha256', ''))) and blob.is_file():
                result['blobs_scanned'] += 1
                sources.extend(layers(blob.read_bytes()[:MAX_LAYER_BYTES], budget))
            for container, data in sources:
                for kind, value, encoding, needle in needles:
                    if needle in data and (kind, event['seq'], container) not in seen:
                        seen.add((kind, event['seq'], container))
                        result['hits'].append({
                            'canary': kind, 'value_preview': value[:4] + '…', 'encoding': encoding,
                            'container': container, 'event_seq': event['seq'], 'event_kind': event.get('kind'),
                            'destination': event.get('sni') or event.get('host') or event.get('name') or event.get('orig_ip'),
                            'port': event.get('orig_port'), 'target': event.get('target'),
                            'body_sha256': body.get('sha256')})
    result['stolen_kinds'] = sorted({hit['canary'].split(':')[0] for hit in result['hits']})
    return result
