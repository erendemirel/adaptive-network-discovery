"""Strategist RUNTIME CONTEXT system prompt line."""

from network_scanner.models import CurrentState, Environment, StrategistInput
from network_scanner.prompts import strategist_runtime_context_line


def test_runtime_context_includes_pending_and_timeout(monkeypatch):
    monkeypatch.setenv("ADAPTIVE_SCAN_NMAP_TIMEOUT", "300")
    st = StrategistInput(
        target="192.168.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(
            strategist_meta={"pending_llm_timing": "T2"},
            anomalies=[],
        ),
        last_result={},
    )
    line = strategist_runtime_context_line(st)
    assert line is not None
    assert "T2" in line
    assert "300" in line
    assert "nmap_timeout" in line


def test_runtime_context_prefers_last_result_anomalies():
    st = StrategistInput(
        target="192.168.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(anomalies=["stale"]),
        last_result={"anomalies": ["nmap_timeout"]},
    )
    line = strategist_runtime_context_line(st)
    assert line is not None
    assert "nmap_timeout" in line
    assert "stale" not in line


def test_runtime_context_falls_back_to_current_state_anomalies():
    st = StrategistInput(
        target="192.168.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(anomalies=["syn_requires_privileges"]),
        last_result={},
    )
    line = strategist_runtime_context_line(st)
    assert line is not None
    assert "syn_requires_privileges" in line
