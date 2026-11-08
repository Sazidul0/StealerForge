"""Bounded static triage. This module never executes the analyzed file."""
import hashlib
import math
import re
from collections import Counter
from itertools import islice, zip_longest
from pathlib import Path

import lief
import pefile
import yara


class StaticAnalyzer:
    def __init__(self, yara_rule_path, min_str_len=6, max_strings=800,
                 max_file_bytes=134217728, yara_timeout_seconds=30):
        if not Path(yara_rule_path).is_file():
            raise FileNotFoundError(f'YARA rules not found: {yara_rule_path}')
        if not 1 <= min_str_len <= 200 or max_strings < 1:
            raise ValueError('Invalid string extraction limits')
        self.min_str_len, self.max_strings = min_str_len, max_strings
        self.max_file_bytes, self.yara_timeout = max_file_bytes, yara_timeout_seconds
        self.yara_rules = yara.compile(filepath=str(yara_rule_path))

    def analyze_binary(self, file_path, label='initial_sample'):
        path = Path(file_path)
        if not path.is_file():
            raise ValueError(f'Not a regular file: {path}')
        with path.open('rb') as stream:
            raw = stream.read(self.max_file_bytes + 1)
        if len(raw) > self.max_file_bytes:
            raise ValueError(f'Artifact exceeds max_file_bytes: {path.name}')
        report = {
            'artifact_label': label, 'filename': path.name, 'size_bytes': len(raw),
            'hashes': {name: hashlib.new(name, raw).hexdigest() for name in ('md5', 'sha1', 'sha256')},
            'overall_entropy': round(self._shannon_entropy(raw), 4), 'warnings': [],
        }
        for name, operation in [('pefile_analysis', lambda: self._run_pefile(raw)),
                                ('lief_analysis', lambda: self._run_lief(str(path))),
                                ('yara_matches', lambda: self._run_yara(raw)),
                                ('strings', lambda: self._extract_strings(raw))]:
            try:
                report[name] = operation()
            except Exception as exc:
                report[name] = {'status': 'failed', 'error': str(exc)}
                report['warnings'].append(f'{name} failed: {type(exc).__name__}')
        return report

    @staticmethod
    def _shannon_entropy(data):
        if not data:
            return 0.0
        return -sum((n / len(data)) * math.log2(n / len(data)) for n in Counter(data).values())

    def _run_pefile(self, raw):
        try:
            pe = pefile.PE(data=raw, fast_load=False)
        except pefile.PEFormatError as exc:
            return {'is_valid_pe': False, 'error': str(exc)}
        try:
            rich = getattr(pe, 'RICH_HEADER', None)
            rich_info = {}
            if rich:
                rich_info = {'xor_key': hex(rich.checksum),
                             'rich_hash_md5': hashlib.md5(rich.clear_data).hexdigest(),
                             'values': list(rich.values)}
            callbacks, warnings = [], []
            tls = getattr(pe, 'DIRECTORY_ENTRY_TLS', None)
            if tls:
                rva = tls.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
                width = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
                if rva > 0:
                    for index in range(64):
                        try:
                            offset = pe.get_offset_from_rva(rva + index * width)
                            if offset < 0 or offset + width > len(raw):
                                warnings.append('TLS callback array exceeds file data')
                                break
                            value = int.from_bytes(raw[offset:offset + width], 'little')
                            if value == 0:
                                break
                            callbacks.append(hex(value))
                        except pefile.PEFormatError:
                            warnings.append('Unmapped TLS callback RVA')
                            break
                    else:
                        warnings.append('TLS callback array limited to 64 entries')
            resources = []
            root = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
            if root:
                for rtype in root.entries:
                    for rid in getattr(getattr(rtype, 'directory', None), 'entries', []):
                        for lang in getattr(getattr(rid, 'directory', None), 'entries', []):
                            entry = getattr(getattr(lang, 'data', None), 'struct', None)
                            if entry is None:
                                continue
                            size = entry.Size
                            # Read file-backed resource bytes; never allocate SizeOfImage.
                            content = pe.get_data(entry.OffsetToData, min(size, len(raw)))
                            resources.append({'type': str(rtype.name or rtype.struct.Id),
                                              'rva': hex(entry.OffsetToData), 'declared_size': size,
                                              'read_size': len(content),
                                              'entropy': round(self._shannon_entropy(content), 3),
                                              'sha256': hashlib.sha256(content).hexdigest()})
            pdb = []
            for debug in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', []):
                name = getattr(getattr(debug, 'entry', None), 'PdbFileName', None)
                if name:
                    pdb.append(name.decode('utf-8', errors='replace').rstrip('\0'))
            return {'is_valid_pe': True, 'imphash': pe.get_imphash(),
                    'compile_timestamp_untrusted': pe.FILE_HEADER.TimeDateStamp,
                    'entry_point_rva': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                    'image_base': hex(pe.OPTIONAL_HEADER.ImageBase), 'rich_header': rich_info,
                    'tls_callbacks': callbacks, 'pdb_paths': pdb, 'resources': resources,
                    'warnings': warnings + pe.get_warnings()}
        finally:
            pe.close()

    def _run_lief(self, file_path):
        binary = lief.PE.parse(file_path)
        if binary is None:
            return {'parsed': False}
        sections = [{'name': sec.name, 'virtual_address': hex(sec.virtual_address),
                     'virtual_size': sec.virtual_size, 'raw_size': sec.sizeof_raw_data,
                     'raw_offset': sec.pointerto_raw_data, 'entropy': round(sec.entropy, 3),
                     'characteristics': [str(c) for c in sec.characteristics_lists]}
                    for sec in binary.sections]
        imports = {imp.name: [entry.name if not entry.is_ordinal else f'ord_{entry.ordinal}'
                              for entry in imp.entries] for imp in binary.imports}
        overlay = bytes(binary.overlay)
        return {'parsed': True, 'has_nx': binary.has_nx, 'has_aslr': binary.is_pie,
                'signature_verification': str(binary.verify_signature()),
                'signature_note': 'PE signature result does not establish publisher trust or revocation status',
                'sections': sections, 'imports': imports,
                'exports': [entry.name for entry in binary.exported_functions],
                'overlay': {'size': len(overlay), 'entropy': round(self._shannon_entropy(overlay), 3),
                            'head_hex': overlay[:64].hex(),
                            'sha256': hashlib.sha256(overlay).hexdigest() if overlay else None}}

    def _run_yara(self, raw):
        results = []
        for match in self.yara_rules.match(data=raw, timeout=self.yara_timeout):
            instances = []
            for string in islice(match.strings, 25):
                for inst in islice(string.instances, 3):
                    instances.append({'identifier': string.identifier, 'offset': inst.offset,
                                      'preview_hex': inst.matched_data[:80].hex(),
                                      'matched_length': inst.matched_length})
            results.append({'rule': match.rule, 'meta': match.meta, 'matched_strings': instances,
                            'preview_limits': {'identifiers': 25, 'instances_each': 3, 'bytes_each': 80}})
        return results

    def _extract_strings(self, raw):
        patterns = [('ascii', rb'[\x20-\x7e]{%d,200}' % self.min_str_len),
                    ('utf-16le', rb'(?:[\x20-\x7e]\x00){%d,200}' % self.min_str_len)]
        high, other = [], {'ascii': [], 'utf-16le': []}
        count = 0
        keywords = re.compile(r'https?://|net\.tcp://|login data|local state|cookies|wallet|tdata|leveldb|'
                              r'crypt|select |appdata|hkey_|software\\|powershell|discord|telegram|\\users\\|'
                              r'\.pdb\b|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?\b|user-agent|password|token|'
                              r'chrome|firefox|steam|filezilla|vpn|electrum|exodus|metamask', re.I)
        for encoding, pattern in patterns:
            for match in re.finditer(pattern, raw):
                count += 1
                value = match.group().decode(encoding)
                item = {'offset': match.start(), 'encoding': encoding, 'value': value}
                if keywords.search(value):
                    if len(high) < self.max_strings:
                        high.append(dict(item, interesting=True))
                elif len(other[encoding]) < self.max_strings:
                    other[encoding].append(item)
        # Alternate encodings so UTF-16 strings (.NET user strings: C2, paths) are not crowded out by ASCII.
        rest = [x for pair in zip_longest(other['ascii'], other['utf-16le']) for x in pair if x]
        selected = (high + rest)[:self.max_strings]
        return {'items': selected, 'candidate_chunks': count, 'omitted_chunks': count - len(selected),
                'max_characters_per_chunk': 200,
                'note': 'Printable chunks only; encrypted strings need additional analysis. Offsets refer to artifact bytes.'}
