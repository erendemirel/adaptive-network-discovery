from __future__ import annotations

import ipaddress
from typing import Any, Literal

from network_scanner.models import Environment

Likelihood = Literal["low", "medium", "high"]
Visibility = Literal["good", "partial", "poor"]


def _bump_likelihood(x: Likelihood) -> Likelihood:
    order: tuple[Likelihood, ...] = ("low", "medium", "high")
    i = order.index(x)
    return order[min(i + 1, len(order) - 1)]


def compute_scan_signals(cur: dict[str, Any], env: Environment) -> dict[str, str]:
    """Rule-based hints for the strategist (small fixed schema)."""
    per_host = list(cur.get("per_host") or [])
    agg_open = list(cur.get("discovered_ports") or [])
    agg_filt = list(cur.get("filtered_ports") or [])
    host_count = int(cur.get("host_count") or 0)
    host_status = str(cur.get("host_status") or "unknown")
    hints = [str(h).lower() for h in (cur.get("reachability_hints") or [])]
    indirect = list(cur.get("indirect_endpoints") or [])

    open_ports_host = 0
    filt_ports_host = 0
    for row in per_host:
        if not isinstance(row, dict):
            continue
        open_ports_host += len(row.get("open_ports") or [])
        filt_ports_host += len(row.get("filtered_ports") or [])

    total_open = len(agg_open) + open_ports_host
    total_filtered = len(agg_filt) + filt_ports_host

    firewall: Likelihood = "low"
    if total_filtered >= 24 and total_open <= 2:
        firewall = "high"
    elif total_filtered >= 10 and total_open <= 4:
        firewall = "medium"
    elif total_filtered >= 6:
        firewall = _bump_likelihood(firewall)
    if any("firewall" in h or "filtered" in h for h in hints):
        firewall = _bump_likelihood(firewall)

    nat: Likelihood = "high" if env.nated_environment else "low"
    if indirect and host_count == 0 and not total_open:
        nat = _bump_likelihood(nat)
    if any("nat" in h or "split" in h or "hairpin" in h for h in hints):
        nat = _bump_likelihood(nat)

    visibility: Visibility
    if host_count > 0 and total_open > 0:
        visibility = "good"
    elif host_count > 0 or total_open > 0:
        visibility = "partial"
    elif host_status in ("down",) and not total_filtered:
        visibility = "poor"
    elif host_status == "unknown" and not per_host and not agg_open:
        visibility = "poor"
    else:
        visibility = "partial"
    if any("timeout" in h or "rate" in h for h in hints):
        visibility = "partial" if visibility == "good" else "poor"

    mismatch = "no"
    seeds = [s.strip() for s in (env.seed_hosts or []) if isinstance(s, str) and s.strip()]
    if seeds and host_count == 0 and not total_open and not total_filtered:
        for s in seeds:
            try:
                ipaddress.ip_address(s)
                mismatch = "yes"
                break
            except ValueError:
                continue

    hint_blob = " ".join(hints)
    cross_inconsistent: Likelihood = "low"
    if any(
        k in hint_blob
        for k in (
            "inconsistent",
            "differs between",
            "changed between",
            "varying results",
            "different backends",
        )
    ):
        cross_inconsistent = "medium"
    if any(k in hint_blob for k in ("load balanc", "round robin", "split between scans")):
        cross_inconsistent = _bump_likelihood(cross_inconsistent)

    middlebox: Likelihood = "low"
    if any(k in hint_blob for k in ("proxy", "reverse proxy", "waf", "redirect chain", "multi-hop")):
        middlebox = "medium"
    if any(k in hint_blob for k in ("mitm", "tls termination", "transparent proxy")):
        middlebox = _bump_likelihood(middlebox)

    return {
        "firewall_likelihood": firewall,
        "nat_split_horizon_likelihood": nat,
        "host_visibility": visibility,
        "seed_vs_scan_mismatch": mismatch,
        "cross_scan_inconsistency_likelihood": cross_inconsistent,
        "middlebox_proxy_likelihood": middlebox,
    }


def refresh_scan_signals(cur: dict[str, Any], env: Environment) -> None:
    cur["scan_signals"] = compute_scan_signals(cur, env)
