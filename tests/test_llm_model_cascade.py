from __future__ import annotations

from unittest.mock import patch

import pytest

from network_scanner.llm_gemma import GemmaStrategist, strategist_model_chain
from network_scanner.models import Environment, StrategistInput


def test_strategist_model_chain_dedup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_FALLBACK", "b, a , gemma4:e2b")
    assert strategist_model_chain("a") == ["a", "b", "gemma4:e2b"]


def test_strategist_model_chain_empty_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_FALLBACK", raising=False)
    assert strategist_model_chain("x") == ["x"]


@patch.object(GemmaStrategist, "_ollama_generate_with_model")
def test_decide_fallback_on_bad_json(mock_gen: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_MODEL", "tiny")
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_FALLBACK", "big")
    good = (
        '{"action":"stop_scan","target":"10.0.0.0/24","phase":"host",'
        '"reason":"done","confidence":0.9}'
    )
    mock_gen.side_effect = ["not json {{{", good]

    s = GemmaStrategist(model="tiny")
    inp = StrategistInput(target="10.0.0.0/24", phase="host", environment=Environment())
    d = s.decide(inp)
    assert d.action == "stop_scan"
    assert mock_gen.call_count == 2
    assert mock_gen.call_args_list[0][0][2] == "tiny"
    assert mock_gen.call_args_list[1][0][2] == "big"


@patch.object(GemmaStrategist, "_ollama_generate_with_model")
def test_decide_clamps_out_of_scope_probe_when_last_model(mock_gen: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_MODEL", "only")
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_FALLBACK", raising=False)
    mock_gen.return_value = (
        '{"action":"nmap_connect_scan","target":"192.168.1.1","phase":"host",'
        '"reason":"x","confidence":0.5}'
    )
    s = GemmaStrategist(model="only")
    inp = StrategistInput(target="172.30.0.0/24", phase="host", environment=Environment())
    d = s.decide(inp)
    assert d.action == "nmap_connect_scan"
    assert d.target == "172.30.0.0/24"
    assert mock_gen.call_count == 1


@patch.object(GemmaStrategist, "_ollama_generate_with_model")
def test_decide_primary_ok_no_second_call(mock_gen: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_MODEL", "only")
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_FALLBACK", raising=False)
    good = (
        '{"action":"stop_scan","target":"10.0.0.0/24","phase":"host",'
        '"reason":"x","confidence":0.5}'
    )
    mock_gen.return_value = good

    s = GemmaStrategist(model="only")
    inp = StrategistInput(target="10.0.0.0/24", phase="host", environment=Environment())
    s.decide(inp)
    assert mock_gen.call_count == 1
