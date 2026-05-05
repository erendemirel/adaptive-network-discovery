from __future__ import annotations

import ipaddress
from typing import Any

from network_scanner.models import Environment

_INVALID_TOKENS = frozenset(
    {
        "",
        "*",
        "all",
        "any",
        "none",
        "everywhere",
        "anywhere",
        "network",
        "subnet",
    }
)


def _parse_scan_target(scan_target: str) -> ipaddress._BaseNetwork | ipaddress._BaseAddress | None:
    s = scan_target.strip()
    if not s:
        return None
    if "/" in s:
        try:
            return ipaddress.ip_network(s, strict=False)
        except ValueError:
            return None
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        try:
            return ipaddress.ip_network(s, strict=False)
        except ValueError:
            return None


def _parse_decision_target(raw: str) -> ipaddress._BaseNetwork | ipaddress._BaseAddress | None:
    s = raw.strip()
    if not s:
        return None
    if "/" in s:
        try:
            return ipaddress.ip_network(s, strict=False)
        except ValueError:
            return None
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        try:
            return ipaddress.ip_network(s, strict=False)
        except ValueError:
            return None


def _per_host_addresses(cur: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for row in cur.get("per_host") or []:
        if isinstance(row, dict):
            a = row.get("address")
            if isinstance(a, str) and a.strip():
                out.add(a.strip())
    return out


def _known_subnet_networks(env: Environment) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for s in env.known_subnets or []:
        if not isinstance(s, str) or not s.strip():
            continue
        try:
            nets.append(ipaddress.ip_network(s.strip(), strict=False))
        except ValueError:
            continue
    return nets


def _ip_in_scan_scope(
    addr: ipaddress._BaseAddress,
    scan_target: str,
    scan_parsed: ipaddress._BaseNetwork | ipaddress._BaseAddress | None,
) -> bool:
    if isinstance(scan_parsed, ipaddress._BaseNetwork):
        return addr in scan_parsed
    if isinstance(scan_parsed, ipaddress._BaseAddress):
        return addr == scan_parsed
    return False


def _network_allowed(
    net: ipaddress._BaseNetwork,
    scan_target: str,
    scan_parsed: ipaddress._BaseNetwork | ipaddress._BaseAddress | None,
) -> bool:
    if isinstance(scan_parsed, ipaddress._BaseNetwork):
        return net.subnet_of(scan_parsed) or net == scan_parsed
    if isinstance(scan_parsed, ipaddress._BaseAddress):
        return net.num_addresses == 1 and net.network_address == scan_parsed
    return False


def _seed_allows(
    candidate: str,
    scan_target: str,
    scan_parsed: ipaddress._BaseNetwork | ipaddress._BaseAddress | None,
    env: Environment,
) -> bool:
    seeds = {s.strip() for s in (env.seed_hosts or []) if isinstance(s, str) and s.strip()}
    if candidate.strip() not in seeds:
        return False
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return candidate.strip() == scan_target.strip()
    if scan_parsed is None:
        return True
    return _ip_in_scan_scope(addr, scan_target, scan_parsed)


def resolve_nmap_target(
    raw: str,
    scan_target: str,
    env: Environment,
    cur: dict[str, Any],
) -> tuple[str, str | None]:
    """
    Return (target_for_nmap, clamp_reason_or_none).
    Keeps strategist choices inside scan scope, seeds, known subnets, and discovered hosts.
    """
    st = scan_target.strip()
    if not st:
        return raw.strip() or "", "empty_scan_target"

    token = raw.strip().lower()
    if token in _INVALID_TOKENS:
        return st, "invalid_placeholder"

    if raw.strip() == st:
        return st, None

    scan_parsed = _parse_scan_target(st)
    parsed = _parse_decision_target(raw)

    if isinstance(parsed, ipaddress._BaseNetwork):
        if _network_allowed(parsed, st, scan_parsed):
            return raw.strip(), None
        return st, "out_of_scope_network"

    if isinstance(parsed, ipaddress._BaseAddress):
        addr = parsed
        if str(addr) in _per_host_addresses(cur):
            return str(addr), None
        if _ip_in_scan_scope(addr, st, scan_parsed):
            return str(addr), None
        for kn in _known_subnet_networks(env):
            if (
                addr in kn
                and scan_parsed is not None
                and _ip_in_scan_scope(addr, st, scan_parsed)
            ):
                return str(addr), None
        if _seed_allows(str(addr), st, scan_parsed, env):
            return str(addr), None
        return st, "out_of_scope_address"

    # Hostname or non-IP string
    if raw.strip() in _per_host_addresses(cur):
        return raw.strip(), None
    if _seed_allows(raw.strip(), st, scan_parsed, env):
        return raw.strip(), None
    return st, "unresolved_hostname"
