from __future__ import annotations

from network_scanner.models import Environment
from network_scanner.scan_signals import compute_scan_signals, refresh_scan_signals


def test_firewall_high_many_filtered_no_open() -> None:
    cur = {
        "discovered_ports": [],
        "filtered_ports": list(range(30)),
        "host_count": 2,
        "host_status": "up",
        "per_host": [],
        "reachability_hints": [],
        "indirect_endpoints": [],
    }
    sig = compute_scan_signals(cur, Environment())
    assert sig["firewall_likelihood"] == "high"


def test_nat_elevated_from_env() -> None:
    cur = {
        "discovered_ports": [80],
        "filtered_ports": [],
        "host_count": 1,
        "host_status": "up",
        "per_host": [],
        "reachability_hints": [],
        "indirect_endpoints": [],
    }
    sig = compute_scan_signals(cur, Environment(nated_environment=True))
    assert sig["nat_split_horizon_likelihood"] == "high"


def test_seed_mismatch_hint() -> None:
    cur = {
        "discovered_ports": [],
        "filtered_ports": [],
        "host_count": 0,
        "host_status": "unknown",
        "per_host": [],
        "reachability_hints": [],
        "indirect_endpoints": [],
    }
    env = Environment(seed_hosts=["192.168.50.1"])
    sig = compute_scan_signals(cur, env)
    assert sig["seed_vs_scan_mismatch"] == "yes"


def test_refresh_mutates_cur() -> None:
    cur: dict = {"discovered_ports": [], "filtered_ports": [], "per_host": []}
    refresh_scan_signals(cur, Environment())
    assert "scan_signals" in cur
    assert "firewall_likelihood" in cur["scan_signals"]
    assert cur["scan_signals"]["cross_scan_inconsistency_likelihood"] == "low"
    assert cur["scan_signals"]["middlebox_proxy_likelihood"] == "low"


def test_cross_scan_inconsistency_from_hints() -> None:
    cur = {
        "discovered_ports": [80],
        "filtered_ports": [],
        "host_count": 2,
        "host_status": "up",
        "per_host": [],
        "reachability_hints": ["inconsistent results between syn attempts"],
        "indirect_endpoints": [],
    }
    sig = compute_scan_signals(cur, Environment())
    assert sig["cross_scan_inconsistency_likelihood"] == "medium"


def test_middlebox_proxy_from_hints() -> None:
    cur = {
        "discovered_ports": [443],
        "filtered_ports": [],
        "host_count": 1,
        "host_status": "up",
        "per_host": [],
        "reachability_hints": ["reverse proxy in path"],
        "indirect_endpoints": [],
    }
    sig = compute_scan_signals(cur, Environment())
    assert sig["middlebox_proxy_likelihood"] == "medium"
