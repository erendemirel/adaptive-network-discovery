"""Compact summaries of the last few completed strategist steps for LLM context (no training)."""

from __future__ import annotations

from typing import Any


def _anomaly_samples(
    result: dict[str, Any], *, max_items: int = 3, max_len: int = 72
) -> list[str]:
    an = result.get("anomalies") or []
    if not an:
        return []
    out: list[str] = []
    for x in an[-max_items:]:
        s = str(x).strip()
        if len(s) > max_len:
            s = s[: max_len - 3] + "..."
        out.append(s)
    return out


def _summarize_result(result: dict[str, Any]) -> str:
    if result.get("stopped"):
        return "session_stopped"
    if result.get("dry_run"):
        return "dry_run_only"
    hints = result.get("reachability_hints") or []
    if hints and not result.get("open_ports") and not result.get("per_host"):
        return "control:" + ",".join(str(h) for h in hints[:3])
    parts: list[str] = []
    op = result.get("open_ports") or []
    if op:
        parts.append(f"+{len(op)} open")
    fp = result.get("filtered_ports") or []
    if fp:
        parts.append(f"{len(fp)} filtered")
    hc = result.get("host_count")
    if hc is not None:
        parts.append(f"{hc} hosts")
    elif result.get("hosts"):
        parts.append(f"{len(result['hosts'])} host rows")
    an = result.get("anomalies") or []
    if an:
        parts.append(f"anomalies:{len(an)}")
    if hints:
        parts.append("hints:" + ",".join(str(h) for h in hints[:2]))
    ec = result.get("exit_code")
    if ec is not None and ec not in (0, 124):
        parts.append(f"exit={ec}")
    return "; ".join(parts) if parts else "no_port_delta"


def build_recent_steps(history: list[dict[str, Any]], *, limit: int = 5) -> list[dict[str, Any]]:
    """Turn orchestrator `history` entries into small dicts for the strategist payload."""
    if limit <= 0 or not history:
        return []
    out: list[dict[str, Any]] = []
    for item in history[-limit:]:
        dec = item.get("decision") or {}
        action = dec.get("_resolved_action") or dec.get("action") or "?"
        res = item.get("result") or {}
        row: dict[str, Any] = {
            "step": item.get("step"),
            "phase": item.get("phase"),
            "action": action,
            "target": dec.get("target"),
            "outcome": _summarize_result(res),
        }
        samples = _anomaly_samples(res)
        if samples:
            row["anomaly_samples"] = samples
        out.append(row)
    return out
