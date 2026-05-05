from __future__ import annotations

import copy
from typing import Any

from network_scanner.models import StrategistInput
from network_scanner.recent_steps import build_recent_steps


def _compact_script_extracts(ex: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in ex.items():
        if isinstance(v, list):
            out[k] = v[:8]
        elif v is not None:
            out[k] = v
    return out


def _trunc(xs: list[Any], limit: int) -> tuple[list[Any], int]:
    if len(xs) <= limit:
        return xs, 0
    return xs[:limit], len(xs) - limit


def compact_strategist_input(
    state: StrategistInput,
    *,
    max_hosts: int = 128,
    max_ports_per_host: int = 48,
    max_aggregate_ports: int = 200,
    max_services: int = 80,
    max_history_items: int = 12,
    max_recent_steps: int = 5,
    max_scripts_per_host: int = 12,
    max_indirect: int = 96,
) -> StrategistInput:
    """Shrink payload for LLM context and stability on large networks."""
    raw = state.model_dump(mode="json")
    cs = raw["current_state"]
    per_host: list[dict[str, Any]] = copy.deepcopy(cs.get("per_host") or [])

    if len(per_host) > max_hosts:
        omitted = len(per_host) - max_hosts
        per_host = per_host[:max_hosts]
        for row in per_host:
            op, o1 = _trunc(row.get("open_ports") or [], max_ports_per_host)
            fp, o2 = _trunc(row.get("filtered_ports") or [], min(max_ports_per_host, 32))
            sv, o3 = _trunc(row.get("services") or [], 24)
            scr, o4 = _trunc(row.get("scripts") or [], max_scripts_per_host)
            row["open_ports"] = op
            row["filtered_ports"] = fp
            row["services"] = sv
            row["scripts"] = scr
            notes = list(row.get("notes") or [])
            if o1:
                notes.append(f"+{o1} more open ports omitted")
            if o2:
                notes.append(f"+{o2} more filtered ports omitted")
            if o3:
                notes.append(f"+{o3} more services omitted")
            if o4:
                notes.append(f"+{o4} more script rows omitted")
            row["notes"] = notes
            if row.get("script_extracts"):
                row["script_extracts"] = _compact_script_extracts(row["script_extracts"])
        per_host.append(
            {
                "address": "__truncated_hosts__",
                "open_ports": [],
                "filtered_ports": [],
                "services": [],
                "scripts": [],
                "notes": [f"{omitted} additional hosts omitted from LLM context"],
            }
        )
    else:
        for row in per_host:
            op, o1 = _trunc(row.get("open_ports") or [], max_ports_per_host)
            fp, o2 = _trunc(row.get("filtered_ports") or [], min(max_ports_per_host, 32))
            sv, o3 = _trunc(row.get("services") or [], 24)
            scr, o4 = _trunc(row.get("scripts") or [], max_scripts_per_host)
            row["open_ports"] = op
            row["filtered_ports"] = fp
            row["services"] = sv
            row["scripts"] = scr
            notes = list(row.get("notes") or [])
            if o1:
                notes.append(f"+{o1} more open ports omitted")
            if o2:
                notes.append(f"+{o2} more filtered ports omitted")
            if o3:
                notes.append(f"+{o3} more services omitted")
            if o4:
                notes.append(f"+{o4} more script rows omitted")
            row["notes"] = notes
            if row.get("script_extracts"):
                row["script_extracts"] = _compact_script_extracts(row["script_extracts"])

    cs["per_host"] = per_host

    d_ports, d_skip = _trunc(cs.get("discovered_ports") or [], max_aggregate_ports)
    f_ports, f_skip = _trunc(cs.get("filtered_ports") or [], min(max_aggregate_ports, 120))
    cs["discovered_ports"] = d_ports
    cs["filtered_ports"] = f_ports
    agg_notes = list(cs.get("aggregate_notes") or [])
    if d_skip:
        agg_notes.append(f"discovered_ports truncated; +{d_skip} more in full state")
    if f_skip:
        agg_notes.append(f"filtered_ports truncated; +{f_skip} more in full state")
    svcs, s_skip = _trunc(copy.deepcopy(cs.get("services") or []), max_services)
    cs["services"] = svcs
    if s_skip:
        agg_notes.append(f"aggregate services truncated; +{s_skip} more in DB/export")
    cs["aggregate_notes"] = agg_notes

    ie, ie_skip = _trunc(copy.deepcopy(cs.get("indirect_endpoints") or []), max_indirect)
    cs["indirect_endpoints"] = ie
    if ie_skip:
        an2 = list(cs.get("aggregate_notes") or [])
        an2.append(f"indirect_endpoints truncated; +{ie_skip} more")
        cs["aggregate_notes"] = an2

    rh, rh_skip = _trunc(list(cs.get("reachability_hints") or []), 16)
    cs["reachability_hints"] = rh
    if rh_skip:
        an3 = list(cs.get("aggregate_notes") or [])
        an3.append(f"reachability_hints truncated; +{rh_skip} more")
        cs["aggregate_notes"] = an3

    raw["current_state"] = cs
    hist = raw.get("history") or []
    raw["recent_steps"] = build_recent_steps(hist, limit=max_recent_steps)
    raw["history"] = hist[-max_history_items:]

    lr = raw.get("last_result") or {}
    if isinstance(lr, dict) and lr.get("hosts"):
        hosts = lr["hosts"]
        if len(hosts) > 64:
            lr = copy.deepcopy(lr)
            lr["hosts"] = hosts[:64]
            lr["hosts_truncated"] = len(hosts) - 64
            raw["last_result"] = lr

    return StrategistInput.model_validate(raw)
