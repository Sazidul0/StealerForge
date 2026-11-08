import json
import pytest
from core.evidence import build_evidence, normalize_arguments, unwrap_report
from core.context_maximizer import ContextWindowMaximizer, serialize_dossier
from core.reporting import audit_citations


def test_cape_fields_and_argument_shapes(cape_report):
    evidence = build_evidence({}, [], cape_report)
    records = evidence['records']
    assert any(r['kind'] == 'extracted_config' for r in records)
    tree = next(r for r in records if r['kind'] == 'process_tree')
    assert tree['data']['parent_id'] == 1
    event = next(r for r in records if r['kind'] == 'api_call')
    assert event['data']['arguments'] == {'DataOut': 'synthetic'}
    assert event['data']['status'] is False
    assert event['data']['thread_id'] == '7'
    assert event['data']['repeated'] == 2
    assert event['source'].endswith('/behavior/processes/0/calls/0')


def test_wrapper_and_lowercase(cape_report):
    cape_report['cape'] = cape_report.pop('CAPE')
    evidence = build_evidence({}, [], {'data': cape_report, 'error': False})
    config = next(r for r in evidence['records'] if r['kind'] == 'extracted_config')
    assert '#/data/cape/configs/' in config['source']


@pytest.mark.parametrize('value', [[], {'error': True}, {'data': {'error': True}}, {'foo': 1}])
def test_invalid_report_rejected(value):
    with pytest.raises(ValueError):
        unwrap_report(value)


def test_arguments_lossless_and_malformed(cape_report):
    assert normalize_arguments({'a': 1}) == {'a': 1}
    assert normalize_arguments(None) == {}
    result = normalize_arguments([{'name': 'x', 'value': 1}, {'name': 'x', 'value': 2}])
    assert result['x']['duplicate_values'] == [1, 2]
    cape_report['behavior']['processes'][0]['calls'][0]['arguments'] = 'invalid'
    evidence = build_evidence({}, [], cape_report)
    assert any('arguments must' in w for w in evidence['coverage']['warnings'])


def test_late_high_value_event_and_full_data_retained(cape_report):
    calls = [{'api': 'NtReadFile', 'arguments': {'path': str(i)}, 'timestamp': str(i)} for i in range(1000)]
    calls.append({'api': 'HttpSendRequestW', 'arguments': {'Data': 'x'*20000}, 'status': False})
    cape_report['behavior']['processes'][0]['calls'] = calls
    evidence = build_evidence({}, [], cape_report)
    dossier = ContextWindowMaximizer(max_calls_per_proc=3).build_from_evidence(evidence)
    selected = [r for r in dossier['records'] if r['kind'] == 'api_call']
    assert len(selected) == 3
    assert any(r['data']['api'] == 'HttpSendRequestW' for r in selected)
    full = [r for r in evidence['records'] if r['kind'] == 'api_call']
    assert len(full) == 1001
    assert len(full[-1]['data']['arguments']['Data']) == 20000
    assert dossier['selection']['truncated_previews'] > 0
    assert dossier['selection']['omitted_by_kind']['api_call'] == 998


def test_hard_budget_and_no_mutation(cape_report):
    evidence = build_evidence({'strings': {'items': ['x'*20000]*500}}, [], cape_report)
    original = json.dumps(evidence)
    packer = ContextWindowMaximizer(target_tokens=1500, chars_per_token=3)
    dossier = packer.build_from_evidence(evidence)
    assert len(serialize_dossier(dossier)) <= 4500
    assert json.dumps(evidence) == original
    small = packer.shrink_dossier(dossier, 4096)
    assert len(serialize_dossier(small)) <= 4096
    assert small['selection']['selected_records'] + small['selection']['omitted_records'] == len(evidence['records'])


def test_small_budget_rejected():
    with pytest.raises(ValueError):
        ContextWindowMaximizer(target_tokens=1)


def test_citations():
    dossier = {'records': [{'id': 'E0000001'}]}
    assert audit_citations('Observed [E0000001]', dossier)['passed']
    assert not audit_citations('Observed [E0000009]', dossier)['passed']
    assert not audit_citations('No citations', dossier)['passed']


def test_strings_are_chunked_and_interesting_chunks_prioritised(cape_report):
    items = [{'value': 'net.tcp://x', 'interesting': True}] + [{'value': f'filler {i}'} for i in range(45)]
    evidence = build_evidence({'strings': {'items': items, 'candidate_chunks': 46}}, [], cape_report)
    chunks = [r for r in evidence['records'] if r['source'].startswith('stage1_initial_static.json#/strings/items/')]
    assert [len(r['data']['strings']['items']) for r in chunks] == [20, 20, 6]
    assert [r['priority'] for r in chunks] == [1, 2, 2]


def test_process_record_keeps_lifetime_and_exit_is_high_priority():
    calls = [{'api': 'NtClose', 'timestamp': '2026-01-01 10:00:00,000', 'arguments': []},
             {'api': 'NtTerminateProcess', 'timestamp': '2026-01-01 10:00:07,000', 'arguments': []}]
    evidence = build_evidence({}, [], {'behavior': {'processes': [{'process_id': 1, 'calls': calls}]}})
    proc = next(r for r in evidence['records'] if r['kind'] == 'process')
    assert proc['data']['call_summary'] == {'call_count': 2, 'first_call': '2026-01-01 10:00:00,000',
                                            'last_call': '2026-01-01 10:00:07,000'}
    assert [r['priority'] for r in evidence['records'] if r['kind'] == 'api_call'] == [4, 1]
