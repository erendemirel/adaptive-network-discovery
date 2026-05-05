"""recent_steps summaries for strategist payload."""

from network_scanner.recent_steps import build_recent_steps
from network_scanner.state_compact import compact_strategist_input
from network_scanner.models import CurrentState, Environment, StrategistInput


def test_build_recent_steps_uses_resolved_action():
    hist = [
        {
            "step": 0,
            "phase": "host",
            "decision": {"action": "nmap_ping", "_resolved_action": "nmap_no_ping", "target": "10.0.0.0/24"},
            "result": {"open_ports": [], "host_count": 0, "exit_code": 0},
        },
        {
            "step": 1,
            "phase": "port",
            "decision": {"action": "nmap_top_ports", "target": "10.0.0.0/24"},
            "result": {"open_ports": [80, 443], "host_count": 2, "exit_code": 0},
        },
    ]
    rs = build_recent_steps(hist, limit=5)
    assert len(rs) == 2
    assert rs[0]["action"] == "nmap_no_ping"
    assert "no_port_delta" in rs[0]["outcome"] or "hosts" in rs[0]["outcome"]
    assert rs[1]["action"] == "nmap_top_ports"
    assert "+2 open" in rs[1]["outcome"]


def test_build_recent_steps_limit():
    hist = [
        {"step": i, "phase": "host", "decision": {"action": "nmap_ping", "target": "x"}, "result": {}}
        for i in range(10)
    ]
    rs = build_recent_steps(hist, limit=3)
    assert len(rs) == 3
    assert rs[0]["step"] == 7
    assert rs[-1]["step"] == 9


def test_build_recent_steps_includes_anomaly_samples():
    hist = [
        {
            "step": 0,
            "phase": "port",
            "decision": {"action": "nmap_syn_scan", "target": "10.0.0.0/24"},
            "result": {"open_ports": [], "exit_code": 124, "anomalies": ["nmap_timeout", "extra_warn"]},
        },
    ]
    rs = build_recent_steps(hist, limit=5)
    assert rs[0].get("anomaly_samples") == ["nmap_timeout", "extra_warn"]


def test_compact_includes_recent_steps():
    inp = StrategistInput(
        target="192.168.0.0/24",
        phase="host",
        environment=Environment(),
        current_state=CurrentState(),
        history=[
            {
                "step": 0,
                "phase": "host",
                "decision": {"action": "nmap_no_ping", "target": "192.168.0.0/24"},
                "result": {"open_ports": [22], "exit_code": 0},
            }
        ],
    )
    compacted = compact_strategist_input(inp, max_recent_steps=5, max_history_items=12)
    assert len(compacted.recent_steps) == 1
    assert compacted.recent_steps[0]["action"] == "nmap_no_ping"
    assert "+1 open" in compacted.recent_steps[0]["outcome"]
