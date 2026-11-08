import json
from pathlib import Path
from unittest.mock import patch

from core.enrichment import run_enrichment


def test_disabled_tools_do_not_run(tmp_path, pe_sample):
    with patch('core.enrichment.run_bounded') as run:
        assert run_enrichment([pe_sample], {}, tmp_path) == []
        run.assert_not_called()


def test_missing_tool_is_recorded(tmp_path, pe_sample):
    result = run_enrichment([pe_sample], {'capa_path': str(tmp_path / 'missing')}, tmp_path)
    assert result[0]['status'] == 'unavailable'


def test_success_preserves_json_and_uses_argument_list(tmp_path, pe_sample):
    def fake_run(command, directory, timeout, max_output_bytes, memory_mb):
        assert command == ['/fake/capa', '-j', '-r', '/rules', '-s', '/signatures', str(pe_sample.resolve())]
        assert timeout == 120 and memory_mb == 2048
        (directory / 'stdout.log').write_bytes(b'{"capabilities":["synthetic test"]}')
        return {'status': 'completed'}
    with patch('core.enrichment.shutil.which', return_value='/fake/capa'), \
         patch('core.enrichment.run_bounded', side_effect=fake_run):
        result = run_enrichment([pe_sample], {'capa_path': 'capa', 'capa_rules_path': '/rules',
                                            'capa_signatures_path': '/signatures'}, tmp_path)
    assert result[0]['status'] == 'completed'
    assert result[0]['result']['capabilities'] == ['synthetic test']
    assert (tmp_path / result[0]['output']).is_file()


def test_timeout_is_recorded(tmp_path, pe_sample):
    with patch('core.enrichment.shutil.which', return_value='/fake/floss'), \
         patch('core.enrichment.run_bounded', return_value={'status': 'timeout'}):
        result = run_enrichment([pe_sample], {'floss_path': 'floss'}, tmp_path)
    assert result[0]['status'] == 'timeout'


def test_mapped_regions_are_not_disassembled_as_disk_pe(tmp_path, pe_sample):
    from core.evidence import sha256_file
    with patch('core.enrichment.shutil.which', return_value='/fake/capa'), \
         patch('core.enrichment.run_bounded') as run:
        results = run_enrichment([pe_sample], {'capa_path': 'capa'}, tmp_path,
                                 {sha256_file(pe_sample): 'emulator_memory_region_not_reconstructed_PE'})
    run.assert_not_called()
    assert results[0]['status'] == 'unsupported'


def test_shellcode_format_is_explicit(tmp_path):
    from core.evidence import sha256_file
    sample = tmp_path / 'code.bin'
    sample.write_bytes(b'\xc3')
    def fake_run(command, directory, **kwargs):
        assert command[1:5] == ['-j', '-f', 'sc64', str(sample.resolve())]
        (directory / 'stdout.log').write_text('{}')
        return {'status': 'completed'}
    with patch('core.enrichment.shutil.which', return_value='/fake/floss'), \
         patch('core.enrichment.run_bounded', side_effect=fake_run):
        results = run_enrichment([sample], {'floss_path': 'floss'}, tmp_path,
                                 {sha256_file(sample): 'shellcode_amd64'})
    assert results[0]['status'] == 'completed'
