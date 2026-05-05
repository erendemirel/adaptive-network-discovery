"""
Heuristic detection of low-value strategist outputs so the LLM model chain can retry
with a fallback model (same mechanism as JSON/validation failures).

Rules are conservative: only flag patterns that usually mean "no real scan work yet",
"stop with zero evidence", or "no executed probe yet but many non-probe steps" (pre-nmap stall,
mostly evasion) / "consecutive timing-template choices before any nmap" (faster fallback) /
"evasion-only loop after a probe with still no discovery",
or "nmap/probe on an address or subnet outside the session scan target".
Disabled via ADAPTIVE_SCAN_LLM_QUALITY=0.
"""

from __future__ import annotations

import os
from typing import Any

from network_scanner.models import CurrentState, StrategistDecision, StrategistInput
from network_scanner.target_policy import resolve_nmap_target

# Actions that run nmap or application probes (anything that can change scan state).
NMAP_AND_PROBE_ACTIONS: frozenset[str] = frozenset(
    {
        "nmap_ping",
        "nmap_ping_tcp",
        "nmap_ping_udp",
        "nmap_no_ping",
        "nmap_syn_scan",
        "nmap_connect_scan",
        "nmap_ack_scan",
        "nmap_window_scan",
        "nmap_udp_scan",
        "nmap_top_ports",
        "nmap_full_port_scan",
        "nmap_service_detection",
        "banner_grab",
        "tls_fingerprint",
        "http_probe",
        "https_probe",
    }
)

# Timing / evasion choices that do not run a new probe by themselves.
EVASION_ONLY_ACTIONS: frozenset[str] = frozenset(
    {
        "retry_with_timing_slow",
        "retry_with_timing_normal",
        "retry_with_fragmentation",
        "retry_with_decoys",
    }
)

# Subset: LLM often stacks these before any nmap; escalate to fallback sooner (see _timing_pre_nmap_threshold).
TIMING_TUNING_ACTIONS: frozenset[str] = frozenset(
    {
        "retry_with_timing_slow",
        "retry_with_timing_normal",
    }
)


def _quality_enabled() -> bool:
    v = os.environ.get("ADAPTIVE_SCAN_LLM_QUALITY", "").strip().lower()
    if v in ("0", "false", "no", "off"):
        return False
    return True


def strategist_quality_enabled() -> bool:
    """True when strategist quality heuristics run (default on). Controlled by ``ADAPTIVE_SCAN_LLM_QUALITY``."""
    return _quality_enabled()


def _stall_threshold_pre() -> int:
    raw = os.environ.get("ADAPTIVE_SCAN_LLM_STALL_THRESHOLD", "").strip()
    if raw:
        try:
            n = int(raw)
            return max(1, n)
        except ValueError:
            pass
    return 3


def _timing_pre_nmap_threshold() -> int | None:
    """
    Consecutive LLM choices of retry_with_timing_slow/normal before any probe, including the
    current decision, that trigger fallback. Default **2** (second timing in a row → try next model).

    Set ``ADAPTIVE_SCAN_LLM_TIMING_PRE_NMAP_THRESHOLD`` to ``0`` / ``off`` / ``false`` / ``no`` / ``none``
    to disable. Values below **2** are treated as disabled.
    """
    raw = os.environ.get("ADAPTIVE_SCAN_LLM_TIMING_PRE_NMAP_THRESHOLD", "").strip()
    if not raw:
        return 2
    if raw.lower() in ("0", "off", "false", "no", "none", "disable"):
        return None
    try:
        n = int(raw)
        if n < 2:
            return None
        return n
    except ValueError:
        return 2


def _stall_threshold_post() -> int | None:
    """
    None = post-probe evasion rule disabled.

    When **unset**, uses the same value as ``ADAPTIVE_SCAN_LLM_STALL_THRESHOLD`` (default 3)
    so fallback can trigger again after a first nmap if the primary model only proposes
    timing/evasion while state still shows no hosts/ports.

    Set to ``0`` / ``off`` / ``false`` / ``no`` / ``none`` to turn this rule off entirely.
    """
    raw = os.environ.get("ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD", "").strip()
    if not raw:
        return _stall_threshold_pre()
    if raw.lower() in ("0", "off", "false", "no", "disable", "none"):
        return None
    try:
        n = int(raw)
        if n < 1:
            return None
        return n
    except ValueError:
        return _stall_threshold_pre()


def _history_decision_dict(row: dict[str, Any]) -> dict[str, Any]:
    d = row.get("decision")
    return d if isinstance(d, dict) else {}


def nmap_or_probe_executed_in_history(history: list[dict[str, Any]]) -> bool:
    """True if any completed step actually ran a probe (uses orchestrator _resolved_action)."""
    for h in history:
        d = _history_decision_dict(h)
        ra = d.get("_resolved_action")
        if isinstance(ra, str) and ra in NMAP_AND_PROBE_ACTIONS:
            return True
    return False


def consecutive_tail_evasion_actions(history: list[dict[str, Any]]) -> int:
    """Trailing completed steps whose raw LLM `action` was evasion-only."""
    n = 0
    for h in reversed(history):
        d = _history_decision_dict(h)
        a = d.get("action")
        if isinstance(a, str) and a in EVASION_ONLY_ACTIONS:
            n += 1
        else:
            break
    return n


def consecutive_tail_timing_tuning_actions(history: list[dict[str, Any]]) -> int:
    """Trailing completed steps whose raw LLM `action` was timing-only (slow/normal, not frag/decoys)."""
    n = 0
    for h in reversed(history):
        d = _history_decision_dict(h)
        a = d.get("action")
        if isinstance(a, str) and a in TIMING_TUNING_ACTIONS:
            n += 1
        else:
            break
    return n


def _resolved_step_ran_probe(row: dict[str, Any]) -> bool:
    """True if this history row executed an nmap/probe (prefers orchestrator ``_resolved_action``)."""
    d = _history_decision_dict(row)
    ra = d.get("_resolved_action")
    if isinstance(ra, str):
        return ra in NMAP_AND_PROBE_ACTIONS
    a = d.get("action")
    return isinstance(a, str) and a in NMAP_AND_PROBE_ACTIONS


def consecutive_tail_non_probe_steps(history: list[dict[str, Any]]) -> int:
    """Trailing completed steps that did not execute an nmap/probe."""
    n = 0
    for h in reversed(history):
        if _resolved_step_ran_probe(h):
            break
        n += 1
    return n


def _current_decision_will_run_probe(decision: StrategistDecision, inp: StrategistInput) -> bool:
    """Whether the strategist choice would run nmap or an app probe (incl. repeat_last → last nmap or top_ports)."""
    if decision.action in NMAP_AND_PROBE_ACTIONS:
        return True
    if decision.action == "repeat_last_action":
        for h in reversed(inp.history):
            if _resolved_step_ran_probe(h):
                return True
        return True
    return False


def _state_has_discovery_signal(cur: CurrentState) -> bool:
    if cur.host_status != "unknown":
        return True
    if cur.discovered_ports or cur.filtered_ports or cur.per_host:
        return True
    if getattr(cur, "host_count", 0) > 0:
        return True
    return False


def _premature_stop_without_probes(
    decision: StrategistDecision, inp: StrategistInput
) -> bool:
    if decision.action != "stop_scan":
        return False
    if nmap_or_probe_executed_in_history(inp.history):
        return False
    if _state_has_discovery_signal(inp.current_state):
        return False
    return True


def _probe_target_out_of_scan_scope(decision: StrategistDecision, inp: StrategistInput) -> bool:
    """True if the model chose a probe on an IP/network outside the session target (runtime would clamp)."""
    if decision.action not in NMAP_AND_PROBE_ACTIONS:
        return False
    st = inp.target.strip()
    if not st:
        return False
    cur = inp.current_state.model_dump(mode="json")
    _, reason = resolve_nmap_target(decision.target, st, inp.environment, cur)
    return reason in ("out_of_scope_address", "out_of_scope_network")


def _pre_nmap_timing_tuning_repeat(
    decision: StrategistDecision, inp: StrategistInput, threshold: int
) -> bool:
    """Before any probe: too many consecutive LLM timing-template choices (slow/normal only)."""
    if nmap_or_probe_executed_in_history(inp.history):
        return False
    if decision.action not in TIMING_TUNING_ACTIONS:
        return False
    tail = consecutive_tail_timing_tuning_actions(inp.history)
    return (tail + 1) >= threshold


def _pre_nmap_non_probe_stall(decision: StrategistDecision, inp: StrategistInput, threshold: int) -> bool:
    """
    Before any probe has run, too many completed steps did not execute nmap/probes (evasion, repeat noise, etc.).
    Uses ``_resolved_action`` on history so alternating evasion with other non-probe actions cannot reset the count.
    """
    if nmap_or_probe_executed_in_history(inp.history):
        return False
    tail = consecutive_tail_non_probe_steps(inp.history)
    if not _current_decision_will_run_probe(decision, inp):
        tail += 1
    return tail >= threshold


def _post_scan_evasion_stall(
    decision: StrategistDecision, inp: StrategistInput, threshold: int
) -> bool:
    if not nmap_or_probe_executed_in_history(inp.history):
        return False
    if _state_has_discovery_signal(inp.current_state):
        return False
    tail = consecutive_tail_evasion_actions(inp.history)
    if decision.action in EVASION_ONLY_ACTIONS:
        tail += 1
    return tail >= threshold


def quality_escalation_reason(decision: StrategistDecision, inp: StrategistInput) -> str | None:
    """
    If non-None, the caller should treat this model's output as failed and try the next
    model in ADAPTIVE_SCAN_LLM_FALLBACK (when available).

    Reasons are stable tokens for logs and tests.
    """
    if not _quality_enabled():
        return None

    pre_t = _stall_threshold_pre()
    post_t = _stall_threshold_post()
    timing_pre_t = _timing_pre_nmap_threshold()

    if _premature_stop_without_probes(decision, inp):
        return "premature_stop_no_probes"

    if _probe_target_out_of_scan_scope(decision, inp):
        return "probe_target_out_of_scope"

    if timing_pre_t is not None and _pre_nmap_timing_tuning_repeat(decision, inp, timing_pre_t):
        return f"pre_nmap_timing_repeat>={timing_pre_t}"

    if _pre_nmap_non_probe_stall(decision, inp, pre_t):
        return f"pre_nmap_stall>={pre_t}"

    if post_t is not None and _post_scan_evasion_stall(decision, inp, post_t):
        return f"post_scan_evasion_stall>={post_t}"

    return None
