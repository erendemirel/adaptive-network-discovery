from __future__ import annotations

import os
import re
from dataclasses import replace
from typing import Any

from network_scanner.models import Environment, RunTuningProposal


def _parse_int_from_rate(s: str) -> int | None:
    m = re.search(r"(\d+)", str(s).strip())
    return int(m.group(1)) if m else None


def _delay_string_to_ms(s: str) -> int | None:
    t = str(s).strip().lower()
    m = re.fullmatch(r"(\d+)\s*(ms|s)?", t)
    if not m:
        return None
    val = int(m.group(1))
    unit = m.group(2) or "ms"
    if unit == "s":
        return val * 1000
    return val


def _timeout_to_seconds(s: str) -> int | None:
    t = str(s).strip().lower()
    m = re.fullmatch(r"(\d+)\s*(s|m|h)?", t)
    if not m:
        return None
    val = int(m.group(1))
    u = m.group(2) or "s"
    if u == "m":
        return val * 60
    if u == "h":
        return val * 3600
    return val


def _timing_allowed_set(*, low_noise: bool, xdr_heavy: bool) -> frozenset[str]:
    """No env knob: fixed safe sets (faster templates excluded under XDR/low-noise)."""
    if low_noise or xdr_heavy:
        return frozenset({"T2", "T3"})
    return frozenset({"T2", "T3", "T4", "T5"})


def _normalize_timing(s: str) -> str | None:
    t = s.strip().upper()
    if re.fullmatch(r"T[0-5]", t):
        return t
    if re.fullmatch(r"[0-5]", t):
        return f"T{t}"
    return None


def _version_intensity_cap() -> tuple[int, int]:
    """(lo, hi) from existing ADAPTIVE_SCAN_VERSION_INTENSITY; else 0..9."""
    lo = 0
    raw = os.environ.get("ADAPTIVE_SCAN_VERSION_INTENSITY", "").strip()
    if raw.isdigit():
        hi = min(9, int(raw))
    else:
        hi = 9
    return lo, hi


def _max_scan_rate_cap(*, ctx: Any) -> int | None:
    """
    Upper bound = min of applicable existing caps (same sources as nmap base / large-net).
    If none are set, the LLM may not override scan rate.
    """
    caps: list[int] = []
    v = _parse_int_from_rate(os.environ.get("ADAPTIVE_SCAN_GLOBAL_MAX_SCAN_RATE", "") or "")
    if v is not None and v > 0:
        caps.append(v)
    if ctx.low_noise:
        v = _parse_int_from_rate(os.environ.get("ADAPTIVE_SCAN_XDR_MAX_SCAN_RATE", "") or "")
        if v is not None and v > 0:
            caps.append(v)
    if ctx.large_network:
        v = _parse_int_from_rate(os.environ.get("ADAPTIVE_SCAN_MAX_SCAN_RATE", "") or "")
        if v is not None and v > 0:
            caps.append(v)
    if not caps:
        return None
    return min(caps)


def _scan_delay_cap_ms(*, ctx: Any) -> int | None:
    """Ceiling from ADAPTIVE_SCAN_SCAN_DELAY only; unset means LLM may not set delay."""
    raw = os.environ.get("ADAPTIVE_SCAN_SCAN_DELAY", "").strip()
    if not raw:
        return None
    return _delay_string_to_ms(raw)


def _host_timeout_cap_s(*, ctx: Any) -> int:
    """Same default as nmap_runner when env unset."""
    raw = os.environ.get("ADAPTIVE_SCAN_HOST_TIMEOUT", "").strip()
    if raw:
        sec = _timeout_to_seconds(raw)
        if sec is not None and sec > 0:
            return sec
    return 600 if ctx.large_network else 300


def tuning_enabled_for_llm() -> bool:
    return os.environ.get("ADAPTIVE_SCAN_LLM_TUNING", "1").lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def apply_llm_tuning_to_context(
    ctx: Any,
    proposal: RunTuningProposal | None,
    *,
    env: Environment,
) -> tuple[Any, dict[str, Any]]:
    """Merge clamped strategist run_tuning into RunContext. Returns (ctx, applied dict for logging/cache)."""
    if not tuning_enabled_for_llm() or proposal is None:
        return ctx, {}

    applied: dict[str, Any] = {}
    low_noise = bool(ctx.low_noise)
    xdr = bool(env.xdr_heavy)
    allowed = _timing_allowed_set(low_noise=low_noise, xdr_heavy=xdr)

    kw: dict[str, Any] = {}
    if proposal.timing:
        nt = _normalize_timing(proposal.timing)
        if nt and nt in allowed:
            kw["llm_timing"] = nt
            applied["timing"] = nt

    if proposal.version_intensity is not None:
        lo, hi = _version_intensity_cap()
        c = max(lo, min(int(proposal.version_intensity), hi))
        kw["llm_version_intensity"] = str(c)
        applied["version_intensity"] = c

    if proposal.max_scan_rate:
        cap = _max_scan_rate_cap(ctx=ctx)
        if cap is not None:
            m = re.search(r"(\d+)", str(proposal.max_scan_rate))
            if m:
                n = max(1, min(int(m.group(1)), cap))
                kw["llm_max_scan_rate"] = str(n)
                applied["max_scan_rate"] = n

    if proposal.scan_delay:
        cap_ms = _scan_delay_cap_ms(ctx=ctx)
        if cap_ms is not None:
            prop_ms = _delay_string_to_ms(str(proposal.scan_delay))
            if prop_ms is not None:
                ms = max(0, min(prop_ms, cap_ms))
                if ms >= 1000 and ms % 1000 == 0:
                    sd = f"{ms // 1000}s"
                else:
                    sd = f"{ms}ms"
                kw["llm_scan_delay"] = sd
                applied["scan_delay"] = sd

    if proposal.host_timeout:
        cap_s = _host_timeout_cap_s(ctx=ctx)
        prop = _timeout_to_seconds(str(proposal.host_timeout))
        if prop is not None:
            sec = max(15, min(prop, cap_s))
            ht = f"{sec}s"
            kw["llm_host_timeout"] = ht
            applied["host_timeout"] = ht

    if kw:
        ctx = replace(ctx, **kw)
    return ctx, applied


def tuning_bounds_prompt_lines(env: Environment) -> str:
    """Describe limits derived from existing operator env (and fixed timing sets)."""
    low_noise = env.low_noise or env.xdr_heavy
    allowed = sorted(_timing_allowed_set(low_noise=low_noise, xdr_heavy=env.xdr_heavy))
    v_lo, v_hi = _version_intensity_cap()

    rate_parts = []
    if os.environ.get("ADAPTIVE_SCAN_GLOBAL_MAX_SCAN_RATE", "").strip():
        rate_parts.append("GLOBAL_MAX_SCAN_RATE")
    if os.environ.get("ADAPTIVE_SCAN_XDR_MAX_SCAN_RATE", "").strip():
        rate_parts.append("XDR_MAX_SCAN_RATE")
    if os.environ.get("ADAPTIVE_SCAN_MAX_SCAN_RATE", "").strip():
        rate_parts.append("MAX_SCAN_RATE (large-network)")
    rate_hint = (
        f"You may suggest max_scan_rate (packets/sec) up to the minimum of: {', '.join(rate_parts)}."
        if rate_parts
        else "Do not set max_scan_rate unless the operator has set ADAPTIVE_SCAN_GLOBAL_MAX_SCAN_RATE "
        "and/or ADAPTIVE_SCAN_XDR_MAX_SCAN_RATE and/or ADAPTIVE_SCAN_MAX_SCAN_RATE (large-network); "
        "those define the ceiling."
    )

    delay_raw = os.environ.get("ADAPTIVE_SCAN_SCAN_DELAY", "").strip()
    delay_hint = (
        f"scan_delay: at most {delay_raw} (from ADAPTIVE_SCAN_SCAN_DELAY)."
        if delay_raw
        else "Do not set scan_delay unless ADAPTIVE_SCAN_SCAN_DELAY is set (it defines the ceiling)."
    )

    lines = [
        "Optional run_tuning (omit if defaults are fine). The runtime clamps every field to operator "
        "limits from existing ADAPTIVE_SCAN_* env vars (see below).",
        f"timing (-T): only {', '.join(allowed)}.",
        f"version_intensity: integer {v_lo}..{v_hi} (cap from ADAPTIVE_SCAN_VERSION_INTENSITY, else 9).",
        rate_hint,
        delay_hint,
        "host_timeout: up to ADAPTIVE_SCAN_HOST_TIMEOUT if set, else 300s (600s when large_network), "
        "minimum 15s.",
    ]
    return "\n".join(lines)
