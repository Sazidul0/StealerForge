import struct
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def pe_sample(tmp_path):
    """Synthetic PE with a RET entry point; parsed/emulated, never launched natively."""
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0xc0)
    key = 0x12345678
    rich = [0x536e6144 ^ key, key, key, key, 0x01020304 ^ key, 3 ^ key]
    struct.pack_into('<6I', data, 0x80, *rich)
    data[0x98:0x9c] = b'Rich'
    struct.pack_into('<I', data, 0x9c, key)
    data[0xc0:0xc4] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0xc4, 0x14c, 1, 0, 0, 0, 224, 0x102)
    start = 0xd8
    struct.pack_into('<H', data, start, 0x10b)
    for offset, value in {4:512, 16:4096, 20:4096, 28:0x400000, 32:4096, 36:512,
                          56:8192, 60:512, 72:0x100000, 76:4096, 80:0x100000, 84:4096, 92:16}.items():
        struct.pack_into('<I', data, start + offset, value)
    struct.pack_into('<HH', data, start + 40, 6, 0)
    struct.pack_into('<HH', data, start + 68, 3, 0x140)
    section = start + 224
    struct.pack_into('<8sIIIIIIHHI', data, section, b'.text', 128, 4096, 512, 512, 0, 0, 0, 0, 0x60000020)
    text = b'\xc3\0SYNTHETIC_TEST_ONLY\0CryptUnprotectData\0Login Data\0Local State\0'
    data[512:512+len(text)] = text
    path = tmp_path / 'synthetic.exe'
    path.write_bytes(data)
    return path


@pytest.fixture
def cape_report():
    return {'info': {'id': 1}, 'CAPE': {'configs': [{'Synthetic': {'C2': 'https://example.invalid'}}],
                                      'payloads': [{'sha256': 'a'*64}]},
            'behavior': {'processtree': [{'pid': 42, 'parent_id': 1, 'name': 'synthetic.exe'}],
                         'summary': {'read_files': ['C:\\Test\\Login Data']},
                         'processes': [{'process_id': 42, 'parent_id': 1, 'process_name': 'synthetic.exe',
                                        'calls': [{'api': 'CryptUnprotectData', 'timestamp': '2026-01-01 00:00:01',
                                                   'thread_id': '7', 'status': False, 'return': '0x0',
                                                   'repeated': 2,
                                                   'arguments': [{'name': 'DataOut', 'value': 'synthetic'}]}]}]}}
