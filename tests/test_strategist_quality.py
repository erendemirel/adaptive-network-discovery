from __future__ import annotations

from unittest.mock import patch

import pytest

from network_scanner.llm_gemma import GemmaStrategist
from network_scanner.models import CurrentState, Environment, StrategistDecision, StrategistInput
from network_scanner.strategist_quality import (
    consecutive_tail_evasion_actions,
    consecutive_tail_non_probe_steps,
    consecutive_tail_timing_tuning_actions,
    nmap_or_probe_executed_in_history,
    quality_escalation_reason,
    strategist_quality_enabled,
)


def _row(action: str, resolved: str | None = None) -> dict:
    ra = resolved if resolved is not None else action
    return {
        "step": 0,
        "phase": "host",
        "decision": {
            "action": action,
            "target": "10.0.0.0/24",
            "phase": "host",
            "_resolved_action": ra,
        },
        "result": {},
    }


def test_nmap_executed_uses_resolved_action() -> None:
    h = [_row("nmap_ping", resolved="nmap_ping")]
    assert nmap_or_probe_executed_in_history(h) is True
    h2 = [_row("retry_with_timing_normal", resolved="retry_with_timing_normal")]
    assert nmap_or_probe_executed_in_history(h2) is False


def test_consecutive_tail_evasion() -> None:
    h = [
        _row("nmap_ping", resolved="nmap_ping"),
        _row("retry_with_timing_normal"),
        _row("retry_with_timing_normal"),
    ]
    assert consecutive_tail_evasion_actions(h) == 2


def test_quality_pre_nmap_stall(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "3")
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_TIMING_PRE_NMAP_THRESHOLD", "0")
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", raising=False)
    h = [_row("retry_with_timing_normal"), _row("retry_with_timing_normal")]
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=h,
    )
    d = StrategistDecision(
        action="retry_with_timing_normal",
        target="10.0.0.0/24",
        phase="host",
        reason="x",
        confidence=0.5,
    )
    assert quality_escalation_reason(d, inp) == "pre_nmap_stall>=3"


def test_pre_nmap_stall_alternating_evasion_and_fragmentation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-probe tail must not reset when alternating evasion-only actions."""
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "3")
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_TIMING_PRE_NMAP_THRESHOLD", "0")
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", raising=False)
    h = [
        _row("retry_with_timing_normal"),
        _row("retry_with_fragmentation"),
    ]
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=h,
    )
    d = StrategistDecision(
        action="retry_with_timing_slow",
        target="10.0.0.0/24",
        phase="host",
        reason="x",
        confidence=0.5,
    )
    assert quality_escalation_reason(d, inp) == "pre_nmap_stall>=3"


def test_pre_nmap_repeat_last_would_run_probe_does_not_stall(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "3")
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_TIMING_PRE_NMAP_THRESHOLD", "0")
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", raising=False)
    h = [_row("retry_with_timing_normal"), _row("retry_with_timing_normal")]
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=h,
    )
    d = StrategistDecision(
        action="repeat_last_action",
        target="10.0.0.0/24",
        phase="host",
        reason="x",
        confidence=0.5,
    )
    assert quality_escalation_reason(d, inp) is None


def test_consecutive_tail_non_probe_steps_counts_resolved() -> None:
    h = [
        _row("retry_with_timing_normal"),
        _row("retry_with_fragmentation"),
        _row("nmap_syn_scan", resolved="nmap_syn_scan"),
    ]
    assert consecutive_tail_non_probe_steps(h) == 0
    h2 = [_row("retry_with_timing_normal"), _row("retry_with_decoys")]
    assert consecutive_tail_non_probe_steps(h2) == 2


def test_consecutive_tail_timing_tuning_actions() -> None:
    h = [_row("retry_with_timing_normal"), _row("retry_with_timing_slow")]
    assert consecutive_tail_timing_tuning_actions(h) == 2
    h2 = [_row("retry_with_timing_normal"), _row("retry_with_fragmentation")]
    assert consecutive_tail_timing_tuning_actions(h2) == 0


def test_pre_nmap_timing_repeat_triggers_on_second(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_TIMING_PRE_NMAP_THRESHOLD", raising=False)
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", raising=False)
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "3")
    h = [_row("retry_with_timing_normal")]
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=h,
    )
    d = StrategistDecision(
        action="retry_with_timing_slow",
        target="10.0.0.0/24",
        phase="host",
        reason="x",
        confidence=0.5,
    )
    assert quality_escalation_reason(d, inp) == "pre_nmap_timing_repeat>=2"


def test_pre_nmap_timing_repeat_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_TIMING_PRE_NMAP_THRESHOLD", "0")
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "3")
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", raising=False)
    h = [_row("retry_with_timing_normal")]
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=h,
    )
    d = StrategistDecision(
        action="retry_with_timing_normal",
        target="10.0.0.0/24",
        phase="host",
        reason="x",
        confidence=0.5,
    )
    assert quality_escalation_reason(d, inp) is None


def test_pre_nmap_timing_repeat_not_after_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_TIMING_PRE_NMAP_THRESHOLD", raising=False)
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", raising=False)
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "3")
    h = [
        _row("nmap_ping", resolved="nmap_ping"),
        _row("retry_with_timing_normal"),
    ]
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=h,
    )
    d = StrategistDecision(
        action="retry_with_timing_normal",
        target="10.0.0.0/24",
        phase="host",
        reason="x",
        confidence=0.5,
    )
    assert quality_escalation_reason(d, inp) is None


def test_quality_pre_nmap_below_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "3")
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_TIMING_PRE_NMAP_THRESHOLD", "0")
    h = [_row("retry_with_timing_normal")]
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=h,
    )
    d = StrategistDecision(
        action="retry_with_timing_normal",
        target="10.0.0.0/24",
        phase="host",
        reason="x",
        confidence=0.5,
    )
    assert quality_escalation_reason(d, inp) is None


def test_strategist_quality_enabled_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_QUALITY", raising=False)
    assert strategist_quality_enabled() is True
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_QUALITY", "0")
    assert strategist_quality_enabled() is False


def test_quality_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_QUALITY", "0")
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "1")
    h = []
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=h,
    )
    d = StrategistDecision(
        action="retry_with_timing_normal",
        target="10.0.0.0/24",
        phase="host",
        reason="x",
        confidence=0.5,
    )
    assert quality_escalation_reason(d, inp) is None


def test_probe_target_out_of_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", raising=False)
    inp = StrategistInput(
        target="172.30.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=[],
    )
    d = StrategistDecision(
        action="nmap_connect_scan",
        target="192.168.1.1",
        phase="service",
        reason="x",
        confidence=0.6,
    )
    assert quality_escalation_reason(d, inp) == "probe_target_out_of_scope"


def test_probe_in_scope_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", raising=False)
    inp = StrategistInput(
        target="172.30.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=[],
    )
    d = StrategistDecision(
        action="nmap_top_ports",
        target="172.30.0.10",
        phase="host",
        reason="x",
        confidence=0.6,
    )
    assert quality_escalation_reason(d, inp) is None


def test_premature_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", raising=False)
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=[],
    )
    d = StrategistDecision(
        action="stop_scan",
        target="10.0.0.0/24",
        phase="host",
        reason="done",
        confidence=0.9,
    )
    assert quality_escalation_reason(d, inp) == "premature_stop_no_probes"


def test_post_scan_stall_defaults_when_post_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset POST_SCAN_STALL mirrors STALL_THRESHOLD (catches primary loop after first nmap)."""
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "3")
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", raising=False)
    h = [
        _row("nmap_no_ping", resolved="nmap_no_ping"),
        _row("retry_with_timing_slow"),
        _row("retry_with_timing_slow"),
    ]
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=h,
    )
    d = StrategistDecision(
        action="retry_with_timing_slow",
        target="10.0.0.0/24",
        phase="host",
        reason="x",
        confidence=0.5,
    )
    assert quality_escalation_reason(d, inp) == "post_scan_evasion_stall>=3"


def test_post_scan_stall_disabled_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", "0")
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "3")
    h = [
        _row("nmap_no_ping", resolved="nmap_no_ping"),
        _row("retry_with_timing_slow"),
        _row("retry_with_timing_slow"),
    ]
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=h,
    )
    d = StrategistDecision(
        action="retry_with_timing_slow",
        target="10.0.0.0/24",
        phase="host",
        reason="x",
        confidence=0.5,
    )
    assert quality_escalation_reason(d, inp) is None


def test_post_scan_stall(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", "2")
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "99")
    h = [
        _row("nmap_ping", resolved="nmap_ping"),
        _row("retry_with_timing_normal"),
    ]
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=h,
    )
    d = StrategistDecision(
        action="retry_with_timing_normal",
        target="10.0.0.0/24",
        phase="host",
        reason="x",
        confidence=0.5,
    )
    assert quality_escalation_reason(d, inp) == "post_scan_evasion_stall>=2"


@patch.object(GemmaStrategist, "_ollama_generate_with_model")
def test_decide_fallback_on_quality_stall(mock_gen: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_MODEL", "tiny")
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_FALLBACK", "big")
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "3")
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_TIMING_PRE_NMAP_THRESHOLD", "0")
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", raising=False)

    bad = (
        '{"action":"retry_with_timing_normal","target":"10.0.0.0/24","phase":"host",'
        '"reason":"wait","confidence":0.5}'
    )
    good = (
        '{"action":"nmap_top_ports","target":"10.0.0.0/24","phase":"host",'
        '"reason":"scan","confidence":0.7}'
    )
    mock_gen.side_effect = [bad, good]

    h = [_row("retry_with_timing_normal"), _row("retry_with_timing_normal")]
    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=h,
    )
    s = GemmaStrategist(model="tiny")
    d = s.decide(inp)
    assert d.action == "nmap_top_ports"
    assert mock_gen.call_count == 2


@patch.object(GemmaStrategist, "_ollama_generate_with_model")
def test_decide_last_model_accepts_low_quality(mock_gen: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_MODEL", "only")
    monkeypatch.delenv("ADAPTIVE_SCAN_LLM_FALLBACK", raising=False)
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "1")

    bad = (
        '{"action":"retry_with_timing_normal","target":"10.0.0.0/24","phase":"host",'
        '"reason":"wait","confidence":0.5}'
    )
    mock_gen.return_value = bad

    inp = StrategistInput(
        target="10.0.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=[],
    )
    s = GemmaStrategist(model="only")
    d = s.decide(inp)
    assert d.action == "retry_with_timing_normal"
    assert mock_gen.call_count == 1
