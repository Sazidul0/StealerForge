from types import SimpleNamespace
from unittest.mock import MagicMock
import pytest
from core.context_maximizer import ContextWindowMaximizer
from core.evidence import build_evidence
from core.llm_intelligence import ClaudeIntelligenceEngine


def setup_client(text='Assessment [E0000001]', stop='end_turn'):
    client = MagicMock()
    client.messages.count_tokens.return_value = SimpleNamespace(input_tokens=1000)
    message = SimpleNamespace(content=[SimpleNamespace(type='text', text=text)], stop_reason=stop,
                              usage=SimpleNamespace(model_dump=lambda: {'input_tokens': 1000, 'output_tokens': 20}))
    client.messages.stream.return_value.__enter__.return_value.get_final_message.return_value = message
    return client


def dossier():
    evidence = build_evidence({'filename': 'test'}, [], {'info': {'id': 1}})
    return ContextWindowMaximizer().build_from_evidence(evidence)


def test_offline_no_api_or_clipboard(tmp_path, monkeypatch):
    monkeypatch.delenv('ANTHROPIC_API_KEY', raising=False)
    client = setup_client()
    engine = ClaudeIntelligenceEngine({'use_api': False}, client)
    assert engine.analyze_dossier(dossier(), tmp_path) == ''
    client.messages.stream.assert_not_called()
    assert engine.last_result['status'] == 'prompt_exported'
    assert (tmp_path / 'claude_maximized_prompt.txt').exists()


def test_missing_key_is_error_not_silent_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv('ANTHROPIC_API_KEY', raising=False)
    engine = ClaudeIntelligenceEngine({'use_api': True, 'anthropic_api_key': 'YOUR-KEY'})
    with pytest.raises(ValueError, match='ANTHROPIC_API_KEY'):
        engine.analyze_dossier(dossier(), tmp_path)


def test_api_completion_and_preflight(tmp_path):
    client = setup_client()
    engine = ClaudeIntelligenceEngine({'use_api': True}, client)
    result = engine.analyze_dossier(dossier(), tmp_path)
    assert '[E0000001]' in result
    assert engine.last_result['status'] == 'completed'
    client.messages.count_tokens.assert_called_once()
    client.messages.stream.assert_called_once()
    assert client.messages.count_tokens.call_args.kwargs['messages'] == client.messages.stream.call_args.kwargs['messages']


@pytest.mark.parametrize('stop', ['max_tokens', 'refusal', 'stop_sequence'])
def test_incomplete_outputs(tmp_path, stop):
    engine = ClaudeIntelligenceEngine({'use_api': True}, setup_client(stop=stop))
    engine.analyze_dossier(dossier(), tmp_path)
    assert engine.last_result['status'] == 'incomplete'
    assert (tmp_path / 'Threat_Intel.partial.md').exists()
    assert not (tmp_path / 'Threat_Intel_and_SOC_Rules.md').exists()


def test_unsupported_citations_need_review(tmp_path):
    engine = ClaudeIntelligenceEngine({'use_api': True}, setup_client(text='Claim [E9999999]'))
    engine.analyze_dossier(dossier(), tmp_path)
    assert engine.last_result['status'] == 'needs_review'


def test_counted_budget_shrinks_before_generation(tmp_path):
    evidence = build_evidence({'strings': {'items': ['abcd'*200]*100}}, [], {'info': {'id': 1}})
    data = ContextWindowMaximizer().build_from_evidence(evidence)
    # Add independent modest records to allow shrinking without a single huge record.
    data['records'] *= 10
    data['selection']['total_records'] = len(data['records'])
    client = setup_client()
    client.messages.count_tokens.side_effect = [SimpleNamespace(input_tokens=12000), SimpleNamespace(input_tokens=1000)]
    engine = ClaudeIntelligenceEngine({'use_api': True, 'input_token_budget': 10000}, client)
    engine.analyze_dossier(data, tmp_path)
    assert client.messages.count_tokens.call_count == 2
    assert len(engine.final_dossier['records']) < len(data['records'])


def test_report_tlp_reaches_exported_prompt_and_api_request(tmp_path):
    ClaudeIntelligenceEngine({'use_api': False, 'report_tlp': 'amber'}).analyze_dossier(dossier(), tmp_path)
    assert 'Report TLP marking: TLP:AMBER\n' in (tmp_path / 'claude_maximized_prompt.txt').read_text()
    client = setup_client()
    ClaudeIntelligenceEngine({'use_api': True}, client).analyze_dossier(dossier(), tmp_path)
    assert client.messages.stream.call_args.kwargs['messages'][0]['content'].startswith('Report TLP marking: TLP:CLEAR\n')
