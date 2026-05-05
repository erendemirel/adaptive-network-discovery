from __future__ import annotations

import os
from typing import Any


def repeat_guard_enabled() -> bool:
    v = os.environ.get("ADAPTIVE_SCAN_REPEAT_GUARD", "").strip().lower()
    return v not in ("0", "false", "no", "off")

# Host discovery probes that often repeat pointlessly once state already shows live targets.
PING_LIKE: frozenset[str] = frozenset(
    {
        "nmap_ping",
        "nmap_ping_tcp",
        "nmap_ping_udp",
        "nmap_no_ping",
    }
)

# Broad subnet sweeps the LLM often alternates (e.g. nmap_no_ping then nmap_top_ports), which bypassed
# "same action as previous step" repeat logic.
BROAD_SUBNET_CLASS: frozenset[str] = PING_LIKE | frozenset({"nmap_top_ports"})

# TCP port sweeps after -sV on the same target are usually redundant (LLM alternates syn <-> -sV).
TCP_PORT_SWEEP: frozenset[str] = frozenset({"nmap_syn_scan", "nmap_connect_scan"})

REDUNDANT_AFTER_SERVICE_DETECTION: frozenset[str] = BROAD_SUBNET_CLASS | TCP_PORT_SWEEP


def _has_open_ports(cur: dict[str, Any]) -> bool:
    if cur.get("discovered_ports"):
        return True
    for row in cur.get("per_host") or []:
        if isinstance(row, dict) and row.get("open_ports"):
            return True
    return False


def _has_live_hosts(cur: dict[str, Any]) -> bool:
    hs = cur.get("host_status")
    if hs in ("up", "filtered"):
        return True
    try:
        if int(cur.get("host_count") or 0) > 0:
            return True
    except (TypeError, ValueError):
        pass
    return bool(cur.get("per_host"))


def apply_nmap_repeat_guard(
    resolved: str,
    nmap_target: str,
    last_nmap_action: str | None,
    last_nmap_target: str | None,
    cur: dict[str, Any],
    *,
    nmap_actions: frozenset[str],
) -> tuple[str, str | None]:
    """
    If the strategist asks for the same executable nmap action on the same target as the
    previous step, remap to the next sensible probe (or stop) so we do not burn max_steps.
    Also catches alternating broad subnet sweeps (ping-like <-> top_ports) and redundant rescans
    (broad class or TCP port sweep) right after nmap_service_detection.
    Returns (possibly_new_resolved, history_note_or_none).
    """
    if last_nmap_action is None or last_nmap_target is None:
        return resolved, None
    if resolved not in nmap_actions:
        return resolved, None
    if last_nmap_target != nmap_target:
        return resolved, None

    # Another discovery/top-ports pass or TCP sweep after -sV on this target is almost never useful.
    if (
        resolved in REDUNDANT_AFTER_SERVICE_DETECTION
        and last_nmap_action == "nmap_service_detection"
        and (_has_open_ports(cur) or _has_live_hosts(cur))
    ):
        return "stop_scan", "repeat_guard:after_service_detection_no_redundant_rescan"

    # Same class, different action (e.g. nmap_top_ports then nmap_no_ping): treat like repeat.
    if (
        resolved in BROAD_SUBNET_CLASS
        and last_nmap_action in BROAD_SUBNET_CLASS
        and last_nmap_action != resolved
        and _has_open_ports(cur)
    ):
        return (
            "nmap_service_detection",
            "repeat_guard:broad_subnet_alternation->nmap_service_detection",
        )

    if last_nmap_action != resolved:
        return resolved, None

    if resolved in PING_LIKE:
        return "nmap_top_ports", "repeat_guard:ping_like->nmap_top_ports"
    if resolved == "nmap_top_ports":
        if _has_open_ports(cur):
            return "nmap_service_detection", "repeat_guard:nmap_top_ports->nmap_service_detection"
        return "stop_scan", "repeat_guard:nmap_top_ports->stop_scan_no_ports"
    if resolved == "nmap_service_detection":
        return "stop_scan", "repeat_guard:nmap_service_detection->stop_scan"
    # SYN/connect sweeps are expensive; a second identical pass is usually noise — escalate to -sV.
    if resolved in ("nmap_syn_scan", "nmap_connect_scan"):
        if _has_open_ports(cur):
            return (
                "nmap_service_detection",
                "repeat_guard:tcp_port_scan->nmap_service_detection",
            )
        return "stop_scan", f"repeat_guard:{resolved}->stop_scan_no_ports"
    return "stop_scan", f"repeat_guard:{resolved}->stop_scan"
