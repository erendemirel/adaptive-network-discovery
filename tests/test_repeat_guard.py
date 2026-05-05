from __future__ import annotations

from network_scanner.orchestrator import NMAP_ACTIONS
from network_scanner.repeat_guard import apply_nmap_repeat_guard


def test_no_guard_first_step() -> None:
    r, note = apply_nmap_repeat_guard(
        "nmap_no_ping",
        "10.0.0.0/24",
        None,
        None,
        {},
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "nmap_no_ping"
    assert note is None


def test_no_guard_different_target() -> None:
    r, note = apply_nmap_repeat_guard(
        "nmap_no_ping",
        "10.0.0.0/24",
        "nmap_no_ping",
        "10.0.1.0/24",
        {},
        nmap_actions=NMAP_ACTIONS,
    )
    assert note is None


def test_ping_like_repeat_to_top_ports() -> None:
    cur = {"host_count": 5, "discovered_ports": []}
    r, note = apply_nmap_repeat_guard(
        "nmap_no_ping",
        "172.30.0.0/24",
        "nmap_no_ping",
        "172.30.0.0/24",
        cur,
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "nmap_top_ports"
    assert note == "repeat_guard:ping_like->nmap_top_ports"


def test_top_ports_repeat_to_service_detection() -> None:
    cur = {"discovered_ports": [80], "per_host": []}
    r, note = apply_nmap_repeat_guard(
        "nmap_top_ports",
        "172.30.0.0/24",
        "nmap_top_ports",
        "172.30.0.0/24",
        cur,
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "nmap_service_detection"
    assert "service_detection" in note


def test_top_ports_repeat_no_ports_stops() -> None:
    cur = {"discovered_ports": [], "per_host": [], "host_count": 0}
    r, note = apply_nmap_repeat_guard(
        "nmap_top_ports",
        "172.30.0.0/24",
        "nmap_top_ports",
        "172.30.0.0/24",
        cur,
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "stop_scan"
    assert "stop_scan" in note


def test_top_ports_repeat_open_ports_only_in_per_host() -> None:
    cur = {"discovered_ports": [], "per_host": [{"address": "1.2.3.4", "open_ports": [22]}]}
    r, note = apply_nmap_repeat_guard(
        "nmap_top_ports",
        "10.0.0.0/24",
        "nmap_top_ports",
        "10.0.0.0/24",
        cur,
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "nmap_service_detection"


def test_syn_scan_repeat_with_ports_to_service_detection() -> None:
    cur = {"discovered_ports": [80, 443], "per_host": []}
    r, note = apply_nmap_repeat_guard(
        "nmap_syn_scan",
        "172.30.0.0/24",
        "nmap_syn_scan",
        "172.30.0.0/24",
        cur,
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "nmap_service_detection"
    assert "tcp_port_scan" in note


def test_syn_scan_repeat_no_ports_stops() -> None:
    cur = {"discovered_ports": [], "per_host": [], "host_count": 0}
    r, note = apply_nmap_repeat_guard(
        "nmap_syn_scan",
        "10.0.0.0/24",
        "nmap_syn_scan",
        "10.0.0.0/24",
        cur,
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "stop_scan"


def test_connect_scan_repeat_with_ports_to_service_detection() -> None:
    cur = {"per_host": [{"address": "10.0.0.1", "open_ports": [22]}]}
    r, note = apply_nmap_repeat_guard(
        "nmap_connect_scan",
        "10.0.0.0/24",
        "nmap_connect_scan",
        "10.0.0.0/24",
        cur,
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "nmap_service_detection"


def test_service_detection_repeat_stops() -> None:
    cur = {"discovered_ports": [80]}
    r, note = apply_nmap_repeat_guard(
        "nmap_service_detection",
        "172.30.0.0/24",
        "nmap_service_detection",
        "172.30.0.0/24",
        cur,
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "stop_scan"


def test_broad_subnet_alternation_no_ping_after_top_ports_to_service_detection() -> None:
    cur = {"discovered_ports": [80, 111], "host_count": 32, "per_host": []}
    r, note = apply_nmap_repeat_guard(
        "nmap_no_ping",
        "172.30.0.0/24",
        "nmap_top_ports",
        "172.30.0.0/24",
        cur,
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "nmap_service_detection"
    assert "broad_subnet_alternation" in (note or "")


def test_after_service_detection_broad_rescan_stops() -> None:
    cur = {"discovered_ports": [80], "host_count": 10, "per_host": []}
    r, note = apply_nmap_repeat_guard(
        "nmap_top_ports",
        "172.30.0.0/24",
        "nmap_service_detection",
        "172.30.0.0/24",
        cur,
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "stop_scan"
    assert "after_service_detection" in (note or "")


def test_after_service_detection_syn_scan_stops() -> None:
    """E2e: model alternates nmap_syn_scan <-> -sV; last was -sV so block another syn sweep."""
    cur = {"discovered_ports": [80, 111], "host_count": 32, "per_host": []}
    r, note = apply_nmap_repeat_guard(
        "nmap_syn_scan",
        "172.30.0.0/24",
        "nmap_service_detection",
        "172.30.0.0/24",
        cur,
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "stop_scan"
    assert "after_service_detection" in (note or "")


def test_alternation_without_open_ports_not_remapped() -> None:
    cur = {"discovered_ports": [], "per_host": [], "host_count": 0}
    r, note = apply_nmap_repeat_guard(
        "nmap_no_ping",
        "10.0.0.0/24",
        "nmap_top_ports",
        "10.0.0.0/24",
        cur,
        nmap_actions=NMAP_ACTIONS,
    )
    assert r == "nmap_no_ping"
    assert note is None
