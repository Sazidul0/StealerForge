from pathlib import Path
import pytest
from core.static_engine import StaticAnalyzer
from core.rule_validator import AutomatedRuleValidator

RULES = Path(__file__).resolve().parents[1] / 'rules/local_stealer_hunting.yar'


def test_real_pe_parsers_and_yara(pe_sample):
    result = StaticAnalyzer(RULES).analyze_binary(pe_sample)
    assert not result['warnings'], result
    assert result['pefile_analysis']['is_valid_pe']
    assert result['pefile_analysis']['rich_header']['xor_key'] == '0x12345678'
    assert result['lief_analysis']['parsed']
    assert result['lief_analysis']['sections'][0]['name'] == '.text'
    assert any(r['rule'] == 'Stealer_Capability_DPAPI_and_SQLite' for r in result['yara_matches'])
    assert all('offset' in item for item in result['strings']['items'])


def test_non_pe_and_string_limit(tmp_path):
    path = tmp_path / 'sample.txt'
    path.write_bytes(b'login data\0local state\0other string 1234\0')
    result = StaticAnalyzer(RULES, max_strings=2).analyze_binary(path)
    assert not result['pefile_analysis']['is_valid_pe']
    assert len(result['strings']['items']) == 2
    assert result['strings']['omitted_chunks'] == 1


def test_missing_rules_and_size_limit(tmp_path, pe_sample):
    with pytest.raises(FileNotFoundError):
        StaticAnalyzer(tmp_path / 'missing')
    with pytest.raises(ValueError):
        StaticAnalyzer(RULES, max_file_bytes=2).analyze_binary(pe_sample)


def yara_report(condition='true', text='SYNTHETIC_TEST_ONLY'):
    return '```YARA\nrule test { strings: $a = "' + text + '" condition: $a and ' + condition + ' }\n```\n'


def test_yara_matching_and_nonmatching(pe_sample, tmp_path):
    validator = AutomatedRuleValidator()
    matched = validator.extract_and_validate(yara_report(), [pe_sample], tmp_path)
    assert matched['status'] == 'checks_passed'
    assert not matched['production_ready']
    failed = validator.extract_and_validate(yara_report(text='NOT_IN_SAMPLE'), [pe_sample], tmp_path)
    assert failed['status'] == 'checks_failed'
    assert failed['yara_validation'][0]['compiled_successfully']
    assert failed['yara_validation'][0]['unmatched_rules'] == ['test']


def test_yara_benign_false_positive(pe_sample, tmp_path):
    result = AutomatedRuleValidator().extract_and_validate(yara_report(), [pe_sample], tmp_path, [pe_sample])
    assert result['status'] == 'checks_failed'
    assert any(result['yara_validation'][0]['benign_hits'].values())


def test_yara_include_disabled(tmp_path, pe_sample):
    report = '```yara\ninclude "secret.yar"\nrule test {condition: true}\n```'
    result = AutomatedRuleValidator().extract_and_validate(report, [pe_sample], tmp_path)
    assert result['status'] == 'checks_failed'


SIGMA = '''title: Synthetic Process Test
id: 232161cc-4656-4bbb-8866-e8d126804ae2
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\synthetic.exe'
  condition: selection
level: low
'''


def test_sigma_condition_parsed(tmp_path):
    validator = AutomatedRuleValidator()
    good = validator.extract_and_validate('```yml\n' + SIGMA + '```', [], tmp_path)
    assert good['status'] == 'checks_passed', good
    bad = validator.extract_and_validate('```yaml\n' + SIGMA.replace('condition: selection', 'condition: missing') + '```', [], tmp_path)
    assert bad['status'] == 'checks_failed', bad


@pytest.mark.parametrize('block', ['- just\n- a list\n', 'title: Empty\n', 'null\n'])
def test_invalid_sigma_blocks(tmp_path, block):
    result = AutomatedRuleValidator().extract_and_validate('```yaml\n' + block + '```', [], tmp_path)
    assert result['status'] == 'checks_failed'


def test_empty_report_not_verified(tmp_path):
    result = AutomatedRuleValidator().extract_and_validate('No supported rules.', [], tmp_path)
    assert result['status'] == 'no_rules'


def test_utf16_strings_are_not_crowded_out_and_keywords_are_marked(tmp_path):
    path = tmp_path / 'sample.bin'
    path.write_bytes(b'\0'.join(b'ascii filler %03d' % i for i in range(10)) + b'\0\0\0'
                     + 'net.tcp://127.0.0.1:1912'.encode('utf-16-le') + b'\0\0'
                     + 'plain wide text'.encode('utf-16-le'))
    items = StaticAnalyzer(RULES, max_strings=4).analyze_binary(path)['strings']['items']
    assert items[0]['value'] == 'net.tcp://127.0.0.1:1912' and items[0]['interesting']
    assert any(i['encoding'] == 'utf-16le' and i['value'] == 'plain wide text' for i in items)
