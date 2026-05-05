from __future__ import annotations

from network_scanner.models import Environment
from network_scanner.target_policy import resolve_nmap_target


def test_invalid_placeholder_clamped() -> None:
    env = Environment()
    cur: dict = {}
    t, reason = resolve_nmap_target("all", "192.168.1.0/24", env, cur)
    assert t == "192.168.1.0/24"
    assert reason == "invalid_placeholder"


def test_ip_inside_scan_cidr() -> None:
    env = Environment()
    cur: dict = {}
    t, reason = resolve_nmap_target("192.168.1.10", "192.168.1.0/24", env, cur)
    assert t == "192.168.1.10"
    assert reason is None


def test_ip_outside_scan_cidr() -> None:
    env = Environment()
    cur: dict = {}
    t, reason = resolve_nmap_target("10.0.0.1", "192.168.1.0/24", env, cur)
    assert t == "192.168.1.0/24"
    assert reason == "out_of_scope_address"


def test_per_host_address_trusted() -> None:
    env = Environment()
    cur = {"per_host": [{"address": "10.0.0.1", "open_ports": [80]}]}
    t, reason = resolve_nmap_target("10.0.0.1", "192.168.5.0/24", env, cur)
    assert t == "10.0.0.1"
    assert reason is None


def test_seed_in_scope() -> None:
    env = Environment(seed_hosts=["192.168.1.77"])
    cur: dict = {}
    t, reason = resolve_nmap_target("192.168.1.77", "192.168.1.0/24", env, cur)
    assert t == "192.168.1.77"
    assert reason is None


def test_seed_out_of_scope_clamped() -> None:
    env = Environment(seed_hosts=["10.0.0.1"])
    cur: dict = {}
    t, reason = resolve_nmap_target("10.0.0.1", "192.168.1.0/24", env, cur)
    assert t == "192.168.1.0/24"
    assert reason == "out_of_scope_address"


def test_subnet_of_scan_allowed() -> None:
    env = Environment()
    cur: dict = {}
    t, reason = resolve_nmap_target("10.0.0.0/28", "10.0.0.0/24", env, cur)
    assert t == "10.0.0.0/28"
    assert reason is None


def test_wider_subnet_clamped() -> None:
    env = Environment()
    cur: dict = {}
    t, reason = resolve_nmap_target("10.0.0.0/16", "10.0.0.0/24", env, cur)
    assert t == "10.0.0.0/24"
    assert reason == "out_of_scope_network"


def test_scan_target_exact_match() -> None:
    env = Environment()
    cur: dict = {}
    t, reason = resolve_nmap_target("192.168.1.0/24", "192.168.1.0/24", env, cur)
    assert t == "192.168.1.0/24"
    assert reason is None
