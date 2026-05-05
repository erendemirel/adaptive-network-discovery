from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from network_scanner.auto_env import apply_environment_adaptation
from network_scanner.db import ScanStore
from network_scanner.llm_gemma import GemmaStrategist
from network_scanner.llm_tuning import apply_llm_tuning_to_context
from network_scanner.models import (
    CurrentState,
    Environment,
    Phase,
    StrategistInput,
)
from network_scanner.nmap_runner import (
    RunContext,
    build_nmap_command,
    merge_state_from_result,
    run_nmap,
    summary_to_result_dict,
)
from network_scanner.repeat_guard import apply_nmap_repeat_guard, repeat_guard_enabled
from network_scanner.scan_signals import refresh_scan_signals
from network_scanner.seeds import load_host_lines, reapply_seed_hosts_to_state
from network_scanner.state_import import merge_peer_final_state
from network_scanner.target_policy import resolve_nmap_target

logger = logging.getLogger(__name__)

NMAP_ACTIONS: frozenset[str] = frozenset(
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


def _xdr_resolve_scan_action(env: Environment, action: str) -> tuple[str, bool]:
    """Remap noisy probes under XDR/low-noise; returns (action, redirected)."""
    if env.xdr_heavy:
        if action == "nmap_syn_scan":
            return "nmap_connect_scan", True
        if action in ("nmap_ping", "nmap_ping_tcp", "nmap_ping_udp"):
            return "nmap_no_ping", True
    elif env.low_noise and action == "nmap_syn_scan":
        return "nmap_connect_scan", True
    return action, False


def _apply_xdr_action_policy(env: Environment, action: str) -> str:
    if env.xdr_heavy or env.low_noise:
        if action in ("retry_with_decoys", "retry_with_fragmentation"):
            return "retry_with_timing_slow"
    return action


def _cache_key(cmd: list[str]) -> str:
    return hashlib.sha256(json.dumps(cmd, default=str).encode("utf-8")).hexdigest()


def _append_ndjson(path: Path | None, row: dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, default=str) + "\n")


@dataclass
class OrchestratorConfig:
    max_steps: int = 20
    db_path: Path = field(
        default_factory=lambda: Path.home() / ".cache" / "adaptive_scan" / "scan.db"
    )
    session_id: str | None = None
    resume_session_id: str | None = None
    llm_max_hosts: int = 128
    llm_max_ports_per_host: int = 48
    llm_max_aggregate_ports: int = 240
    llm_max_services: int = 120
    llm_max_history: int = 12
    llm_max_recent_steps: int = 5
    merge_state_path: Path | None = None
    merge_peer_scanner_id: str | None = None
    resume_restore_environment: bool = True
    persist_connect_after_syn_fail: bool = True
    ndjson_log_path: Path | None = None
    initial_current_state: dict[str, Any] | None = None
    dry_run: bool = False
    ipv6: bool = False
    seed_hosts_path: Path | None = None
    reload_seeds_interval_s: float = 0.0
    reload_seeds_on_mtime: bool = False


@dataclass
class OrchestratorResult:
    session_id: str
    target: str
    final_state: dict[str, Any]
    history: list[dict[str, Any]]
    dry_run: bool = False
    dry_run_nmap_argv: list[str] | None = None
    final_environment: Environment | None = None


class AdaptiveScanner:
    def __init__(self, config: OrchestratorConfig) -> None:
        self._cfg = config
        self._strategist = GemmaStrategist(
            llm_max_hosts=config.llm_max_hosts,
            llm_max_ports_per_host=config.llm_max_ports_per_host,
            llm_max_aggregate_ports=config.llm_max_aggregate_ports,
            llm_max_services=config.llm_max_services,
            llm_max_history=config.llm_max_history,
            llm_max_recent_steps=config.llm_max_recent_steps,
        )
        self._last_seed_mtime: float = 0.0
        self._last_seed_reload_mono: float = time.monotonic()

    def _maybe_reload_seeds(self, env: Environment, cur: dict[str, Any]) -> tuple[Environment, dict[str, Any]]:
        p = self._cfg.seed_hosts_path
        if not p or not p.exists():
            return env, cur
        do_reload = False
        if self._cfg.reload_seeds_on_mtime:
            m = p.stat().st_mtime
            if m > self._last_seed_mtime:
                self._last_seed_mtime = m
                do_reload = True
        if self._cfg.reload_seeds_interval_s > 0:
            now = time.monotonic()
            if now - self._last_seed_reload_mono >= self._cfg.reload_seeds_interval_s:
                self._last_seed_reload_mono = now
                do_reload = True
        if do_reload:
            lines = load_host_lines(p)
            env = reapply_seed_hosts_to_state(env, cur, lines)
        return env, cur

    def run(self, target: str, environment: Environment) -> OrchestratorResult:
        env = environment.model_copy()
        store = ScanStore(self._cfg.db_path)
        ttl = float((os.environ.get("ADAPTIVE_SCAN_CACHE_TTL", "") or "0").strip() or "0")

        history: list[dict[str, Any]] = []
        phase: Phase = "host"
        last_action: str | None = None
        last_result: dict[str, Any] = {}
        session_prefer_connect = False
        last_nmap_action: str | None = None
        last_nmap_target: str | None = None
        dry_run_argv: list[str] | None = None
        start_step = 0

        cur: dict[str, Any] = copy.deepcopy(self._cfg.initial_current_state) or CurrentState().model_dump()
        cur.setdefault("strategist_meta", {})
        cur.setdefault("reachability_hints", [])
        cur.setdefault("indirect_endpoints", [])
        cur.setdefault("aggregate_notes", [])
        cur.setdefault("anomalies", [])
        cur.setdefault("scan_signals", {})

        if self._cfg.merge_state_path and self._cfg.merge_state_path.exists():
            raw = json.loads(self._cfg.merge_state_path.read_text(encoding="utf-8"))
            fs = raw.get("final_state") if isinstance(raw, dict) else None
            if fs is None and isinstance(raw, dict):
                fs = raw
            peer = (self._cfg.merge_peer_scanner_id or (raw.get("scanner_id") if isinstance(raw, dict) else None) or "imported")
            if isinstance(fs, dict):
                cur = merge_peer_final_state(cur, fs, str(peer))

        if self._cfg.resume_session_id:
            session_id = self._cfg.resume_session_id
            chk = store.load_checkpoint(session_id)
            if chk:
                start_step = int(chk.get("completed_steps", 0))
                if self._cfg.resume_restore_environment:
                    env = Environment.model_validate(chk["environment"])
                cur = chk["current_state"]
                history = list(chk.get("history", []))
                phase = chk.get("phase", "host")
                last_action = chk.get("last_action")
                last_result = dict(chk.get("last_result", {}))
                session_prefer_connect = bool(chk.get("session_prefer_connect", False))
                last_nmap_action = chk.get("last_nmap_action")
                last_nmap_target = chk.get("last_nmap_target")
        else:
            session_id = self._cfg.session_id or str(uuid.uuid4())
            store.new_session(session_id, target)

        env = reapply_seed_hosts_to_state(env, cur, list(env.seed_hosts))
        if self._cfg.seed_hosts_path and self._cfg.seed_hosts_path.exists():
            self._last_seed_mtime = self._cfg.seed_hosts_path.stat().st_mtime
            env = reapply_seed_hosts_to_state(env, cur, load_host_lines(self._cfg.seed_hosts_path))

        executed_nmap_in_dry_run = False

        for step in range(start_step, self._cfg.max_steps):
            env, cur = self._maybe_reload_seeds(env, cur)
            refresh_scan_signals(cur, env)

            inp = StrategistInput(
                target=target,
                phase=phase,
                environment=env,
                current_state=CurrentState.model_validate(cur),
                last_action=last_action,
                last_result=last_result,
                history=history[-self._cfg.llm_max_history :],
            )
            decision_raw = self._strategist.decide(inp)
            nmap_target, clamp_reason = resolve_nmap_target(
                decision_raw.target, target, env, cur
            )
            if clamp_reason or decision_raw.target.strip() != nmap_target:
                logger.info(
                    "Strategist target resolved: llm=%r nmap=%r reason=%s",
                    decision_raw.target,
                    nmap_target,
                    clamp_reason or "normalized",
                )
            decision = decision_raw.model_copy(update={"target": nmap_target})
            env = apply_environment_adaptation(env, decision.environment_adaptation)
            if env.xdr_heavy:
                session_prefer_connect = True

            action = _apply_xdr_action_policy(env, decision.action)
            resolved, xdr_redir = _xdr_resolve_scan_action(env, action)
            phase = decision.phase

            if resolved == "repeat_last_action":
                resolved = last_nmap_action or "nmap_top_ports"

            repeat_guard_note: str | None = None
            if repeat_guard_enabled():
                gr, rg_note = apply_nmap_repeat_guard(
                    resolved,
                    nmap_target,
                    last_nmap_action,
                    last_nmap_target,
                    cur,
                    nmap_actions=NMAP_ACTIONS,
                )
                if rg_note:
                    resolved = gr
                    repeat_guard_note = rg_note
                    ra = _apply_xdr_action_policy(env, resolved)
                    r2, xr2 = _xdr_resolve_scan_action(env, ra)
                    resolved = r2
                    xdr_redir = xdr_redir or xr2
                    logger.info(
                        "Repeat guard: same nmap as previous step -> %s (%s)",
                        resolved,
                        rg_note,
                    )

            hist_decision = decision.model_dump(mode="json")
            hist_decision["_resolved_action"] = resolved
            hist_decision["_xdr_redirect"] = xdr_redir
            if clamp_reason:
                hist_decision["_target_clamp_reason"] = clamp_reason
            if decision_raw.target.strip() != nmap_target:
                hist_decision["_raw_llm_target"] = decision_raw.target
            if repeat_guard_note:
                hist_decision["_repeat_guard"] = repeat_guard_note

            if resolved == "stop_scan":
                history.append(
                    {
                        "step": step,
                        "phase": phase,
                        "decision": hist_decision,
                        "result": {"stopped": True},
                    }
                )
                store.append_event(session_id, phase, resolved, hist_decision, {"stopped": True})
                _append_ndjson(
                    self._cfg.ndjson_log_path,
                    {"session_id": session_id, "step": step, "decision": hist_decision, "result": {"stopped": True}},
                )
                store.save_checkpoint(
                    session_id,
                    {
                        "completed_steps": step + 1,
                        "environment": env.model_dump(mode="json"),
                        "current_state": cur,
                        "history": history,
                        "phase": phase,
                        "last_action": resolved,
                        "last_result": last_result,
                        "session_prefer_connect": session_prefer_connect,
                        "last_nmap_action": last_nmap_action,
                        "last_nmap_target": last_nmap_target,
                    },
                )
                break

            if resolved not in NMAP_ACTIONS:
                synth: dict[str, Any] = {
                    "command": [],
                    "anomalies": [],
                    "reachability_hints": [],
                    "host_likely_up": bool(cur.get("discovered_ports") or cur.get("per_host")),
                }
                meta = dict(cur.get("strategist_meta") or {})
                if resolved == "retry_with_timing_slow":
                    meta["pending_llm_timing"] = "T2"
                    synth["reachability_hints"] = ["strategist_retry_timing_slow"]
                elif resolved == "retry_with_timing_normal":
                    meta.pop("pending_llm_timing", None)
                cur["strategist_meta"] = meta

                history.append({"step": step, "phase": phase, "decision": hist_decision, "result": synth})
                store.append_event(session_id, phase, resolved, hist_decision, synth)
                _append_ndjson(
                    self._cfg.ndjson_log_path,
                    {"session_id": session_id, "step": step, "decision": hist_decision, "result": synth},
                )
                last_action = resolved
                last_result = synth
                store.save_checkpoint(
                    session_id,
                    {
                        "completed_steps": step + 1,
                        "environment": env.model_dump(mode="json"),
                        "current_state": cur,
                        "history": history,
                        "phase": phase,
                        "last_action": last_action,
                        "last_result": last_result,
                        "session_prefer_connect": session_prefer_connect,
                        "last_nmap_action": last_nmap_action,
                        "last_nmap_target": last_nmap_target,
                    },
                )
                continue

            ctx = RunContext(
                discovered_ports=list(cur.get("discovered_ports") or []),
                stealth=env.stealth_required,
                latency=env.latency,
                large_network=env.large_network,
                low_noise=env.low_noise,
                prefer_connect=True if session_prefer_connect else None,
                ipv6=self._cfg.ipv6,
            )
            sm = dict(cur.get("strategist_meta") or {})
            if sm.get("pending_llm_timing"):
                ctx = replace(ctx, llm_timing=sm.pop("pending_llm_timing"))
                cur["strategist_meta"] = sm

            ctx, tuning_applied = apply_llm_tuning_to_context(ctx, decision.run_tuning, env=env)
            if tuning_applied:
                hist_decision = dict(hist_decision)
                hist_decision["run_tuning_applied"] = tuning_applied

            if self._cfg.dry_run and not executed_nmap_in_dry_run:
                argv = build_nmap_command(resolved, nmap_target, ctx)
                executed_nmap_in_dry_run = True
                dry_run_argv = argv
                history.append(
                    {
                        "step": step,
                        "phase": phase,
                        "decision": hist_decision,
                        "result": {"dry_run": True, "command": argv},
                    }
                )
                store.append_event(session_id, phase, resolved, hist_decision, {"dry_run": True, "command": argv})
                return OrchestratorResult(
                    session_id=session_id,
                    target=target,
                    final_state=cur,
                    history=history,
                    dry_run=True,
                    dry_run_nmap_argv=argv,
                    final_environment=env,
                )

            result_dict: dict[str, Any]
            if ttl > 0:
                cmd = build_nmap_command(resolved, nmap_target, ctx)
                key = _cache_key(cmd)
                hit = store.cache_get(key, max_age_s=ttl)
                if hit is not None:
                    result_dict = hit
                else:
                    summary, _ = run_nmap(resolved, nmap_target, ctx)
                    result_dict = summary_to_result_dict(summary)
                    if summary.exit_code in (0, 124) and not any(
                        x in (result_dict.get("anomalies") or []) for x in ("nmap_missing",)
                    ):
                        store.cache_set(key, result_dict)
            else:
                summary, _ = run_nmap(resolved, nmap_target, ctx)
                result_dict = summary_to_result_dict(summary)

            if (
                "syn_requires_privileges" in (result_dict.get("anomalies") or [])
                and self._cfg.persist_connect_after_syn_fail
                and resolved == "nmap_syn_scan"
            ):
                session_prefer_connect = True
                ctx_fb = replace(ctx, prefer_connect=True)
                ctx_fb, _ = apply_llm_tuning_to_context(ctx_fb, decision.run_tuning, env=env)
                summary2, _ = run_nmap("nmap_connect_scan", nmap_target, ctx_fb)
                result_dict = summary_to_result_dict(summary2)
                resolved = "nmap_connect_scan"

            cur = merge_state_from_result(cur, result_dict)
            last_nmap_action = resolved
            last_nmap_target = nmap_target
            last_action = resolved
            last_result = result_dict

            _an = result_dict.get("anomalies") or []
            _hc = int(result_dict.get("host_count") or 0)
            _op = len(result_dict.get("open_ports") or [])
            logger.info(
                "Orchestrator step %s merged action=%s target=%s exit_code=%s host_count=%s open_ports=%s anomalies=%s",
                step,
                resolved,
                nmap_target,
                result_dict.get("exit_code"),
                _hc,
                _op,
                _an,
            )

            history.append(
                {
                    "step": step,
                    "phase": phase,
                    "decision": hist_decision,
                    "result": result_dict,
                }
            )
            store.append_event(session_id, phase, resolved, hist_decision, result_dict)
            _append_ndjson(
                self._cfg.ndjson_log_path,
                {"session_id": session_id, "step": step, "decision": hist_decision, "result": result_dict},
            )
            store.save_checkpoint(
                session_id,
                {
                    "completed_steps": step + 1,
                    "environment": env.model_dump(mode="json"),
                    "current_state": cur,
                    "history": history,
                    "phase": phase,
                    "last_action": last_action,
                    "last_result": last_result,
                    "session_prefer_connect": session_prefer_connect,
                    "last_nmap_action": last_nmap_action,
                    "last_nmap_target": last_nmap_target,
                },
            )

        return OrchestratorResult(
            session_id=session_id,
            target=target,
            final_state=cur,
            history=history,
            dry_run=False,
            dry_run_nmap_argv=dry_run_argv,
            final_environment=env,
        )
