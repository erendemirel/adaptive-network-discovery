"""GemmaStrategist JSON parsing helpers (prose + markdown + multiple `{` spans)."""

import pytest

from network_scanner.llm_gemma import (
    STRATEGIST_OLLAMA_JSON_SCHEMA,
    _coerce_strategist_decision_dict,
    _extract_json_object,
    _ollama_format_field,
)


def test_extract_plain_json():
    d = _extract_json_object('{"action": "stop_scan", "target": "x", "phase": "host", "reason": "r", "confidence": 0.5}')
    assert d["action"] == "stop_scan"


def test_extract_after_prose():
    raw = 'Here you go:\n```json\n{"action": "stop_scan", "target": "1.2.3.4", "phase": "port", "reason": "done", "confidence": 0.9}\n```'
    d = _extract_json_object(raw)
    assert d["action"] == "stop_scan"


def test_extract_second_object_when_first_invalid():
    text = 'not json { broken } then {"action": "nmap_no_ping", "target": "0.0.0.0/0", "phase": "host", "reason": "x", "confidence": 0.3}'
    d = _extract_json_object(text)
    assert d["action"] == "nmap_no_ping"


def test_strip_gemma_style_tokens():
    raw = '<|think|>blah<|end|>{"action": "stop_scan", "target": "t", "phase": "host", "reason": "r", "confidence": 1.0}'
    d = _extract_json_object(raw)
    assert d["action"] == "stop_scan"


@pytest.fixture
def clear_ollama_chat_format(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLLAMA_CHAT_FORMAT", raising=False)


def test_ollama_format_gemma_schema_default(clear_ollama_chat_format: None) -> None:
    assert _ollama_format_field("gemma4:e2b") == STRATEGIST_OLLAMA_JSON_SCHEMA


def test_ollama_format_qwen_json_default(clear_ollama_chat_format: None) -> None:
    assert _ollama_format_field("qwen2.5-coder:1.5b") == "json"
    assert _ollama_format_field("qwen2.5:0.5b") == "json"


def test_coerce_history_shaped_qwen_payload() -> None:
    nested = {
        "step": 6,
        "phase": "host",
        "decision": {
            "action": "retry_with_timing_slow",
            "target": "172.30.0.0/24",
            "outcome": "control:strategist_retry_timing_slow",
        },
        "result": {
            "command": [],
            "anomalies": [],
            "reachability_hints": ["strategist_retry_timing_slow"],
            "host_likely_up": False,
        },
    }
    flat = _coerce_strategist_decision_dict(nested)
    assert flat["action"] == "retry_with_timing_slow"
    assert flat["target"] == "172.30.0.0/24"
    assert flat["phase"] == "host"
    assert flat["reason"] == "control:strategist_retry_timing_slow"
    assert flat["confidence"] == 0.55


def test_coerce_leaves_flat_payload_unchanged() -> None:
    d = {
        "action": "nmap_no_ping",
        "target": "10.0.0.0/24",
        "phase": "host",
        "reason": "x",
        "confidence": 0.7,
    }
    assert _coerce_strategist_decision_dict(d) is d


def test_coerce_flat_partial_action_target_outcome() -> None:
    """Small Qwen sometimes omits phase/reason/confidence; use outcome as reason."""
    d = {
        "action": "retry_with_timing_slow",
        "target": "172.30.0.0/24",
        "outcome": "control:strategist_retry_timing_slow",
    }
    out = _coerce_strategist_decision_dict(d)
    assert out["phase"] == "host"
    assert out["reason"] == "control:strategist_retry_timing_slow"
    assert out["confidence"] == 0.55
    assert out["action"] == "retry_with_timing_slow"
