from core.cti import build_telemetry, render_advisory
from core.evidence import build_evidence


def test_cti_preserves_extraction_and_separates_observation_from_capability(cape_report):
    attack = {'id': 'T1555.003', 'tactic': 'Credential Access', 'technique': 'Credentials from Password Stores',
              'subtechnique': 'Credentials from Web Browsers'}
    enrichment = [{'tool': 'capa', 'status': 'completed', 'artifact_sha256': 'a' * 64,
                   'result': {'rules': {'read browser data': {'meta': {'att&ck': [attack]}}}}},
                  {'tool': 'floss', 'status': 'completed', 'artifact_sha256': 'a' * 64,
                   'result': {'strings': {'stack_strings': [{'string': '<script>alert(1)</script>|x', 'offset': 42}]}}}]
    config = {'cncs': ['https://example.invalid'], 'key': {'encoding': 'hex', 'value': '010203'}}
    local = {'stages': [{'engine': 'cape_parser', 'status': 'completed', 'input_sha256': 'a' * 64,
                        'result': {'parser': 'Synthetic', 'config_found': True, 'config': config}},
                       {'engine': 'speakeasy', 'status': 'partial',
                        'result': {'report_data': {'entry_points': [{'apis': [{'api_name': 'CreateMutexW', 'ret_val': 0}]}]}}}]}
    evidence = build_evidence({'hashes': {'sha256': 'a' * 64}}, [], cape_report,
                              enrichment=enrichment, local_results=local)
    telemetry = build_telemetry({'filename': 'synthetic.exe'}, evidence, {'artifact_retention': 'ephemeral'})
    assert telemetry['configurations'][-1]['config'] == config
    assert telemetry['attack'][0]['id'] == 'T1555.003'
    assert telemetry['attack'][0]['evidence_class'] == 'static_capability_not_observed_execution'
    assert telemetry['attack'][0]['evidence'][0]['artifact_sha256'] == 'a' * 64
    assert telemetry['behavior']['emulated'][0]['data']['ret_val'] == 0
    assert any(e['data'].get('status') is False for e in telemetry['behavior']['cape'] if isinstance(e['data'], dict))
    assert telemetry['classification']['attribution'] == 'unconfirmed'
    report = render_advisory(telemetry)
    assert report.count('\n## ') == 5
    assert '<script>' not in report and '&lt;script&gt;' in report
    assert 'T1555.003' in report


def test_no_findings_are_not_a_clean_verdict():
    evidence = build_evidence({}, [], {'info': {'analysis_mode': 'static_only'}})
    telemetry = build_telemetry({}, evidence, {})
    assert not telemetry['attack'] and not telemetry['configurations']
    assert telemetry['classification']['attribution'] == 'unconfirmed'
    assert 'does not establish' in render_advisory(telemetry)


def test_attack_deduplication_keeps_both_sources():
    rule = {'meta': {'att&ck': [{'id': 'T1055', 'tactic': 'Defense Evasion'}]}}
    evidence = build_evidence({}, [], {'info': {}}, enrichment=[
        {'tool': 'capa', 'status': 'completed', 'result': {'rules': {'one': rule, 'two': rule}}}])
    telemetry = build_telemetry({}, evidence, {})
    assert len(telemetry['attack']) == 1
    assert len(telemetry['attack'][0]['evidence']) == 2
