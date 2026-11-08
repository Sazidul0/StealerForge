"""Isolated entry points for optional libraries. Invoked by the local orchestrator."""
import argparse
import hashlib
import importlib
import importlib.metadata
import json
import re
import sys
from pathlib import Path


def json_safe(value):
    if isinstance(value, bytes):
        return {'encoding': 'hex', 'value': value.hex()}
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (tuple, list, set)):
        return [json_safe(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f'Unsupported parser result type: {type(value).__name__}')


def write_json(path, value):
    Path(path).write_text(json.dumps(json_safe(value), ensure_ascii=True, indent=2), encoding='utf-8')


def memory_priority(region, image_base):
    """Keep later sample allocations ahead of the emulator's many support mappings."""
    tag = str(region.tag).lower()
    if any(term in tag for term in ('virtualalloc', 'heap', 'malloc', 'mapview', 'allocatememory')):
        return 0
    if region.base == image_base:
        return 1
    if not tag.startswith('emu.'):
        return 2
    if tag.startswith('emu.stack'):
        return 3
    return 4


def run_speakeasy(sample, output, options):
    import speakeasy
    from speakeasy.config import get_default_config_dict
    config = get_default_config_dict()
    config['timeout'] = options['emulation_seconds']
    config['max_api_count'] = options['max_api_calls']
    config['max_instructions'] = options['max_instructions']
    # Payload bytes are acquired into scratch files, never embedded in exported reports.
    config['snapshot_memory_regions'] = False
    config['keep_memory_on_free'] = True
    # No host filesystem volumes, GDB listener, or custom host network handlers.
    se = speakeasy.Speakeasy(config=config)
    outcome = {'engine': 'speakeasy', 'version': importlib.metadata.version('speakeasy-emulator'),
               'status': 'completed', 'artifacts': [], 'coverage_warnings': [],
               'memory_selection': 'Allocation/heap/view tags, input image, other non-emu mappings, stack, support mappings',
               'evidence_class': 'emulated_behavior_not_observed_windows_execution'}
    image_base = None
    try:
        if options.get('shellcode_arch'):
            image_base = se.load_shellcode(str(sample), arch=options['shellcode_arch'])
            se.run_shellcode(image_base)
        else:
            module = se.load_module(str(sample))
            image_base = module.base
            se.run_module(module, all_entrypoints=options.get('all_entrypoints', False), emulate_children=False)
    except Exception as exc:
        outcome.update(status='partial', error=f'{type(exc).__name__}: {exc}')
    try:
        report = json.loads(se.get_json_report())
        report.pop('data', None)  # Speakeasy's compressed memory payload table, if supplied.
        write_json(output / 'report.json', report)
        outcome['report'] = 'report.json'
        for ep in report.get('entry_points', []):
            if ep.get('error'):
                outcome['status'] = 'partial'
                outcome['coverage_warnings'].append('An emulated entry point reported an error; inspect report.json')
        if not report.get('entry_points'):
            outcome['status'] = 'partial'
            outcome['coverage_warnings'].append('No emulated entry points were reported')
    except Exception as exc:
        outcome.update(status='failed', report_error=str(exc))
    total = 0
    seen = set()
    dumps = output / 'dumps'
    dumps.mkdir(exist_ok=True)
    try:
        for region in sorted(se.get_mem_maps(), key=lambda r: memory_priority(r, image_base)):
            base, size = region.base, region.size
            record = {'base': hex(base), 'size_bytes': size, 'tag': str(region.tag),
                      'selection_priority': memory_priority(region, image_base),
                      'representation': 'emulator_memory_region_not_reconstructed_PE'}
            if size <= 0 or size > options['max_region_bytes']:
                record['status'] = 'skipped_region_limit'
            elif len(seen) >= options['max_dumps'] or total + size > options['max_dump_bytes']:
                record['status'] = 'skipped_total_limit'
            else:
                try:
                    data = se.mem_read(base, size)
                    digest = hashlib.sha256(data).hexdigest()
                    record['sha256'] = digest
                    if digest in seen:
                        record['status'] = 'duplicate'
                    else:
                        path = dumps / f'{digest}.bin'
                        path.write_bytes(data)
                        seen.add(digest)
                        total += len(data)
                        record.update(status='captured', path=str(path.relative_to(output)))
                except Exception as exc:
                    record.update(status='failed', error=str(exc))
            outcome['artifacts'].append(record)
    except Exception as exc:
        outcome['status'] = 'partial'
        outcome['coverage_warnings'].append(f'Memory acquisition unavailable: {exc}')
    finally:
        se.shutdown()
    if any(r['status'] in ('failed', 'skipped_region_limit', 'skipped_total_limit') for r in outcome['artifacts']):
        outcome['status'] = 'partial'
        outcome['coverage_warnings'].append('Some emulated memory regions were not captured; inspect artifact outcomes')
    write_json(output / 'result.json', outcome)


def scan_cape_yara(sample, output, options):
    import yara
    root = Path(options['rules_path'])
    candidates = sorted(p for p in root.rglob('*') if p.suffix in ('.yar', '.yara') and 'deprecated' not in p.parts)
    result = {'engine': 'cape_yara', 'status': 'completed', 'matches': [], 'errors': [],
              'rules_files_total': len(candidates), 'rules_files_scanned': 0}
    if not candidates:
        raise ValueError('No CAPE YARA rule files found')
    for path in candidates:
        try:
            # Each rule file gets a separate namespace/compile so a bad file cannot hide other hits.
            rules = yara.compile(filepath=str(path), externals={'filename': ''})
            hits = rules.match(filepath=str(sample), externals={'filename': sample.name}, timeout=options['yara_timeout_seconds'])
            result['rules_files_scanned'] += 1
            for hit in hits:
                result['matches'].append({'rule': hit.rule, 'meta': hit.meta, 'rule_file': str(path.relative_to(root))})
        except Exception as exc:
            result['errors'].append({'file': str(path.relative_to(root)), 'error': str(exc)})
    if result['errors']:
        result['status'] = 'partial'
    write_json(output / 'result.json', result)


def load_cape_parser(name):
    import cape_parsers
    if not re.fullmatch(r'[A-Za-z0-9_]+', name):
        raise ValueError('Parser name must be an installed CAPE module name')
    module = None
    for group in ('core', 'community'):
        path = Path(cape_parsers.__file__).parent / 'CAPE' / group / f'{name}.py'
        if path.is_file():
            module = importlib.import_module(f'cape_parsers.CAPE.{group}.{name}')
            break
    if module is None or not callable(getattr(module, 'extract_config', None)):
        raise ValueError(f'Installed parser does not expose extract_config(data): {name}')
    return module


def run_cape_parser(sample, output, options):
    name = options['parser_name']
    module = load_cape_parser(name)
    config = module.extract_config(sample.read_bytes())
    write_json(output / 'result.json', {'engine': 'cape_parser', 'parser': name,
               'version': importlib.metadata.version('CAPE-parsers'), 'status': 'completed',
               'config_found': bool(config), 'config': config,
               'note': 'Parser output is a candidate extraction and requires validation against source bytes'})


def user_strings(heap):
    """Every string in a .NET #US heap: compressed length, UTF-16LE text, one trailing flag byte."""
    values, offset = [], 1
    while offset < len(heap):
        first = heap[offset]
        if first & 0x80 == 0:
            size, offset = first, offset + 1
        elif first & 0xC0 == 0x80 and offset + 1 < len(heap):
            size, offset = ((first & 0x3F) << 8) | heap[offset + 1], offset + 2
        elif first & 0xE0 == 0xC0 and offset + 3 < len(heap):
            size = ((first & 0x1F) << 24) | (heap[offset + 1] << 16) | (heap[offset + 2] << 8) | heap[offset + 3]
            offset += 4
        else:
            break
        if size == 0:
            continue
        text = heap[offset:offset + size - 1].decode('utf-16-le', errors='replace')
        offset += size
        if text.strip():
            values.append(text)
    return values


def run_dotnet_metadata(sample, output, options):
    """Names and literals a .NET stealer carries in its metadata: types, P/Invoke imports, resources, user strings."""
    import dnfile
    pe = dnfile.dnPE(str(sample))
    try:
        net = pe.net
        if net is None or net.mdtables is None:
            write_json(output / 'result.json', {'engine': 'dotnet_metadata', 'status': 'not_applicable'})
            return
        tables = net.mdtables
        rows = lambda table: list(getattr(tables, table, None) or [])  # noqa: E731
        assembly = rows('Assembly')
        types = [f'{t.TypeNamespace}.{t.TypeName}'.lstrip('.') for t in rows('TypeDef')]
        pinvoke = []
        for row in rows('ImplMap'):
            scope = getattr(getattr(row, 'ImportScope', None), 'row', None)
            pinvoke.append({'module': str(getattr(scope, 'Name', '')), 'function': str(row.ImportName)})
        heap = getattr(net, 'user_strings', None)
        raw = heap.__data__ if heap is not None and hasattr(heap, '__data__') else b''
        limit = options.get('max_user_strings', 5000)
        strings = user_strings(bytes(raw))
        write_json(output / 'result.json', {
            'engine': 'dotnet_metadata', 'status': 'completed',
            'assembly': {'name': str(assembly[0].Name), 'version': f'{assembly[0].MajorVersion}.{assembly[0].MinorVersion}.'
                                                                    f'{assembly[0].BuildNumber}.{assembly[0].RevisionNumber}'}
                        if assembly else None,
            'assembly_references': sorted({str(r.Name) for r in rows('AssemblyRef')}),
            'types': types[:options.get('max_types', 3000)], 'type_count': len(types),
            'method_count': len(rows('MethodDef')),
            'pinvoke': pinvoke[:1000],
            'resources': [{'name': str(r.Name)} for r in rows('ManifestResource')][:500],
            'user_strings': strings[:limit], 'user_string_count': len(strings),
            'note': 'Metadata names and literals are capability and attribution indicators, not observed execution'})
    finally:
        pe.close()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('engine', choices=['speakeasy', 'cape_yara', 'cape_parser', 'inventory', 'dotnet_metadata'])
    parser.add_argument('--sample')
    parser.add_argument('--output', required=True)
    parser.add_argument('--options', required=True)
    args = parser.parse_args(argv)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    try:
        options = json.loads(Path(args.options).read_text())
        if args.engine == 'inventory':
            import cape_parsers
            names = sorted({p.stem for group in ('core', 'community')
                            for p in (Path(cape_parsers.__file__).parent / 'CAPE' / group).glob('*.py')
                            if not p.name.startswith('_')})
            checks = []
            for name in sorted(set(('RedLine', 'Vidar', 'Stealc', 'Lumma')) | set(options.get('parser_names', []))):
                try:
                    load_cape_parser(name)
                    checks.append({'parser': name, 'status': 'importable'})
                except Exception as exc:
                    checks.append({'parser': name, 'status': 'failed', 'error': f'{type(exc).__name__}: {exc}'})
            status = 'partial' if any(c['status'] == 'failed' for c in checks) else 'completed'
            write_json(output / 'result.json', {'status': status, 'parsers': names,
                       'parser_import_checks': checks,
                       'note': 'Parser filenames are an inventory; import checks do not validate real-family extraction coverage',
                       'versions': {p: importlib.metadata.version(p) for p in
                                    ('CAPE-parsers', 'speakeasy-emulator', 'flare-floss', 'flare-capa', 'numpy')}})
        else:
            sample = Path(args.sample).resolve()
            if sample.stat().st_size > options['max_file_bytes']:
                raise ValueError('Input exceeds worker byte limit')
            functions = {'speakeasy': run_speakeasy, 'cape_yara': scan_cape_yara, 'cape_parser': run_cape_parser,
                         'dotnet_metadata': run_dotnet_metadata}
            functions[args.engine](sample, output, options)
        return 0
    except Exception as exc:
        write_json(output / 'result.json', {'engine': args.engine, 'status': 'failed',
                                          'error': f'{type(exc).__name__}: {exc}'})
        return 1


if __name__ == '__main__':
    sys.exit(main())
