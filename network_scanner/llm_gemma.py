from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import httpx
from pydantic import ValidationError

from network_scanner.llm_tuning import tuning_bounds_prompt_lines, tuning_enabled_for_llm
from network_scanner.models import VALID_ACTIONS, StrategistDecision, StrategistInput
from network_scanner.prompts import (
    STRATEGIST_RUNTIME_CONTEXT_HEADER,
    STRATEGIST_SYSTEM,
    STRATEGIST_XDR_NAT_SECTION,
    strategist_runtime_context_line,
    strategist_user_payload,
)
from network_scanner.state_compact import compact_strategist_input
from network_scanner.strategist_quality import (
    quality_escalation_reason,
    strategist_quality_enabled,
)
from network_scanner.target_policy import resolve_nmap_target

logger = logging.getLogger(__name__)

# Ollama structured output: object schema is stricter than format: "json" for some models (e.g. Gemma 4).
STRATEGIST_OLLAMA_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": sorted(VALID_ACTIONS)},
        "target": {"type": "string"},
        "phase": {
            "type": "string",
            "enum": ["host", "port", "service", "validation"],
        },
        "reason": {"type": "string"},
        "confidence": {"type": "number"},
        "run_tuning": {"type": "object"},
        "environment_adaptation": {"type": "object"},
    },
    "required": ["action", "target", "phase", "reason", "confidence"],
}


def _normalize_model_text_for_json(text: str) -> str:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.I)
    if fence:
        text = fence.group(1).strip()
    # Strip Gemma / Qwen-style control tokens that can precede JSON
    text = re.sub(r"<\|[^>]*\|>", "", text)
    return text.strip()


def _extract_json_object(text: str) -> dict[str, Any]:
    text = _normalize_model_text_for_json(text)
    if not text:
        raise ValueError("empty model response")
    # Try every balanced `{...}` span (model may emit prose or a bad first `{` before the real object)
    last_json_err: str | None = None
    for start in (i for i, c in enumerate(text) if c == "{"):
        depth = 0
        for i in range(start, len(text)):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    blob = text[start : i + 1]
                    try:
                        return json.loads(blob)
                    except json.JSONDecodeError as e:
                        last_json_err = str(e)
                        break
        else:
            continue
    if "{" not in text:
        raise ValueError("no JSON object in response")
    raise ValueError(f"no valid JSON object in response ({last_json_err or 'unbalanced braces'})")


def _coerce_strategist_decision_dict(data: dict[str, Any]) -> dict[str, Any]:
    """
    Some models (e.g. small Qwen) echo history-shaped JSON: {step, phase, decision:{action,...}, result}.
    Normalize to a flat StrategistDecision payload.
    """
    if isinstance(data.get("action"), str) and data["action"].strip():
        ph = data.get("phase")
        rs = data.get("reason")
        cf = data.get("confidence")
        complete = (
            isinstance(ph, str)
            and ph in ("host", "port", "service", "validation")
            and isinstance(rs, str)
            and rs.strip()
            and isinstance(cf, (int, float))
        )
        if complete:
            return data
        out = dict(data)
        out["action"] = data["action"].strip()
        if not (isinstance(ph, str) and ph in ("host", "port", "service", "validation")):
            out["phase"] = "host"
        if not (isinstance(rs, str) and rs.strip()):
            oc = data.get("outcome")
            out["reason"] = (
                oc.strip() if isinstance(oc, str) and oc.strip() else "model_partial_json"
            )
        if not isinstance(cf, (int, float)):
            out["confidence"] = 0.55
        else:
            out["confidence"] = max(0.0, min(1.0, float(cf)))
        if not isinstance(out.get("target"), str):
            out["target"] = ""
        logger.debug("Coerced partial flat strategist JSON action=%s", out["action"])
        return out
    dec = data.get("decision")
    if not isinstance(dec, dict):
        return data
    act = dec.get("action")
    if not isinstance(act, str) or not act.strip():
        return data
    phase_raw = dec.get("phase") if isinstance(dec.get("phase"), str) else None
    if not phase_raw:
        phase_raw = data.get("phase") if isinstance(data.get("phase"), str) else None
    phase = (
        phase_raw
        if phase_raw in ("host", "port", "service", "validation")
        else "host"
    )
    reason = dec.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        outc = dec.get("outcome")
        reason = (
            outc
            if isinstance(outc, str) and outc.strip()
            else "model_emitted_history_shaped_json"
        )
    conf = dec.get("confidence")
    if not isinstance(conf, (int, float)):
        conf = 0.55
    conf = max(0.0, min(1.0, float(conf)))
    tgt = dec.get("target")
    out: dict[str, Any] = {
        "action": act.strip(),
        "target": tgt.strip() if isinstance(tgt, str) else "",
        "phase": phase,
        "reason": reason.strip() if isinstance(reason, str) else str(reason),
        "confidence": conf,
    }
    for k in ("run_tuning", "environment_adaptation"):
        if k in dec and dec[k] is not None:
            out[k] = dec[k]
    logger.debug("Coerced nested strategist JSON (history-shaped) to flat decision action=%s", act)
    return out


def _log_strategist_llm_failure(
    *,
    model: str,
    stage: str,
    raw: str,
    data: dict[str, Any] | None = None,
    exc: BaseException | None = None,
) -> None:
    """Emit one ERROR block so failures are visible without -v when level is INFO."""
    raw_cap = 6000
    tail = "…" if len(raw) > raw_cap else ""
    raw_head = raw[:raw_cap] + tail
    if data is not None:
        try:
            parsed = json.dumps(data, indent=2, default=str)
        except TypeError:
            parsed = repr(data)
        if len(parsed) > 5000:
            parsed = parsed[:5000] + "…"
    else:
        parsed = "(no dict — parse failed before validation)"
    exc_s = f" {exc!r}" if exc else ""
    logger.error(
        "Strategist LLM failure [%s] model=%s%s\n--- parsed JSON ---\n%s\n--- raw model text ---\n%s",
        stage,
        model,
        exc_s,
        parsed,
        raw_head,
    )


def _ollama_think_flag(model: str) -> bool | None:
    """Ollama /api/chat `think` field. None = omit (server default)."""
    v = os.environ.get("OLLAMA_THINK", "").strip().lower()
    if v in ("1", "true", "yes"):
        return True
    if v in ("0", "false", "no"):
        return False
    # Gemma 4: omit `think` so Ollama applies library defaults. Forcing think=false breaks
    # structured JSON output with some Ollama builds (see ollama/ollama#15260).
    return None


def _ollama_format_field(model: str) -> Any | None:
    """Ollama `format` on /api/chat and /api/generate: omit, loose \"json\", or JSON Schema object."""
    v = os.environ.get("OLLAMA_CHAT_FORMAT", "").strip().lower()
    if v in ("0", "none", "off", "false"):
        return None
    if v == "json":
        return "json"
    if v == "schema":
        return STRATEGIST_OLLAMA_JSON_SCHEMA
    m = model.lower()
    if m.startswith("gemma4"):
        return STRATEGIST_OLLAMA_JSON_SCHEMA
    # Small Qwen coder/instruct models: schema support varies; loose json helps structured replies.
    if m.startswith("qwen2.5-coder") or m.startswith("qwen2.5"):
        return "json"
    return None


def _ollama_options(model: str | None = None) -> dict[str, Any]:
    opts: dict[str, Any] = {"temperature": 0.2}
    if model and model.lower().startswith("gemma4"):
        opts["temperature"] = 0.0
    raw = os.environ.get("OLLAMA_OPTIONS", "").strip()
    if not raw:
        return opts
    try:
        extra = json.loads(raw)
        if isinstance(extra, dict):
            opts.update(extra)
    except json.JSONDecodeError:
        pass
    return opts


def _ollama_use_generate_api(model: str) -> bool:
    """Gemma 4 chat templates often produce conversational text; /api/generate + prompt works better."""
    v = os.environ.get("OLLAMA_USE_GENERATE_API", "").strip().lower()
    if v in ("0", "false", "no", "chat"):
        return False
    if v in ("1", "true", "yes", "generate"):
        return True
    return model.lower().startswith("gemma4")


def _ollama_post(base_url: str, path: str, body: dict[str, Any], timeout_s: float) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    hto = httpx.Timeout(timeout_s, connect=min(60.0, timeout_s))
    with httpx.Client(timeout=hto) as client:
        r = client.post(url, json=body)
        if r.is_error:
            snippet = (r.text or "")[:4000]
            raise httpx.HTTPStatusError(
                f"Ollama {path} {r.status_code}: {snippet or r.reason_phrase}",
                request=r.request,
                response=r,
            )
        return r.json()


def _apply_keep_alive(body: dict[str, Any]) -> None:
    """Optional Ollama unload hint between strategist models (e.g. ADAPTIVE_SCAN_OLLAMA_KEEP_ALIVE=0)."""
    v = os.environ.get("ADAPTIVE_SCAN_OLLAMA_KEEP_ALIVE", "").strip()
    if not v:
        return
    if v.isdigit():
        body["keep_alive"] = int(v)
    else:
        body["keep_alive"] = v


def _ollama_timeout_seconds() -> float:
    """Seconds for Ollama HTTP read (model load + generation)."""
    raw = os.environ.get("OLLAMA_TIMEOUT", "").strip()
    if raw:
        try:
            return max(30.0, float(raw))
        except ValueError:
            pass
    # Gemma 4 on CPU / cold start often exceeds 120s for the first completion.
    return 900.0


def strategist_model_chain(primary: str) -> list[str]:
    """
    Ordered list: primary (OLLAMA_MODEL) then ADAPTIVE_SCAN_LLM_FALLBACK tags (comma-separated).
    Duplicates are skipped. Used to retry strategist calls on parse/validation failures and on
    strategist_quality heuristics (evasion-only stall, premature stop without probes).
    """
    p = primary.strip()
    out: list[str] = [p] if p else []
    raw = os.environ.get("ADAPTIVE_SCAN_LLM_FALLBACK", "").strip()
    for part in raw.split(","):
        tag = part.strip()
        if tag and tag not in out:
            out.append(tag)
    return out if out else [os.environ.get("OLLAMA_MODEL", "gemma4:e2b").strip() or "gemma4:e2b"]


class GemmaStrategist:
    """Calls Ollama /api/chat or /api/generate (Gemma 4 defaults to generate) or compatible servers."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout_s: float | None = None,
        *,
        llm_max_hosts: int = 128,
        llm_max_ports_per_host: int = 48,
        llm_max_aggregate_ports: int = 200,
        llm_max_services: int = 80,
        llm_max_history: int = 12,
        llm_max_recent_steps: int = 5,
    ) -> None:
        self.base_url = (base_url or os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")).rstrip(
            "/"
        )
        self.model = model or os.environ.get("OLLAMA_MODEL", "gemma4:e2b")
        self._model_chain = strategist_model_chain(self.model)
        self.timeout_s = float(timeout_s) if timeout_s is not None else _ollama_timeout_seconds()
        self._compact_kw = {
            "max_hosts": llm_max_hosts,
            "max_ports_per_host": llm_max_ports_per_host,
            "max_aggregate_ports": llm_max_aggregate_ports,
            "max_services": llm_max_services,
            "max_history_items": llm_max_history,
            "max_recent_steps": llm_max_recent_steps,
        }

    def decide(self, state: StrategistInput) -> StrategistDecision:
        compacted = compact_strategist_input(state, **self._compact_kw)
        payload = compacted.model_dump(mode="json")
        th = (
            tuning_bounds_prompt_lines(compacted.environment)
            if tuning_enabled_for_llm()
            else None
        )
        user = strategist_user_payload(
            json.dumps(payload, indent=2),
            environment_dict=compacted.environment.model_dump(mode="json"),
            tuning_hint=th,
        )
        sys_prompt = STRATEGIST_SYSTEM
        env = compacted.environment
        if env.xdr_heavy or env.nated_environment or env.low_noise:
            sys_prompt = STRATEGIST_SYSTEM + "\n" + STRATEGIST_XDR_NAT_SECTION
        rc = strategist_runtime_context_line(compacted)
        if rc:
            sys_prompt = f"{sys_prompt}\n\n{STRATEGIST_RUNTIME_CONTEXT_HEADER}\n{rc}"

        last_exc: BaseException | None = None
        for try_model in self._model_chain:
            try:
                raw = self._ollama_generate_with_model(sys_prompt, user, try_model)
            except (httpx.HTTPStatusError, httpx.RequestError) as e:
                logger.warning("Strategist Ollama request failed model=%s: %r", try_model, e)
                last_exc = e
                continue
            except ValueError as e:
                logger.warning("Strategist Ollama empty/unexpected response model=%s: %s", try_model, e)
                last_exc = e
                continue

            try:
                data = _extract_json_object(raw)
            except ValueError as e:
                _log_strategist_llm_failure(
                    model=try_model, stage="json_parse", raw=raw, data=None, exc=e
                )
                last_exc = e
                if try_model != self._model_chain[-1]:
                    logger.info("Strategist JSON parse failed model=%s; trying fallback", try_model)
                continue

            data = _coerce_strategist_decision_dict(data)
            try:
                decision = StrategistDecision.model_validate(data)
            except ValidationError as e:
                _log_strategist_llm_failure(
                    model=try_model, stage="pydantic_validate", raw=raw, data=data, exc=e
                )
                last_exc = e
                if try_model != self._model_chain[-1]:
                    logger.info("Strategist pydantic validate failed model=%s; trying fallback", try_model)
                continue

            try:
                decision.validate_action()
            except ValueError as e:
                _log_strategist_llm_failure(
                    model=try_model, stage="invalid_action", raw=raw, data=data, exc=e
                )
                last_exc = e
                if try_model != self._model_chain[-1]:
                    logger.info("Strategist invalid action model=%s; trying fallback", try_model)
                continue

            q_reason = quality_escalation_reason(decision, state)
            if q_reason:
                if try_model != self._model_chain[-1]:
                    logger.info(
                        "Strategist quality check failed model=%s (%s); trying fallback",
                        try_model,
                        q_reason,
                    )
                    last_exc = ValueError(q_reason)
                    continue
                logger.warning(
                    "Strategist quality check failed model=%s (%s); no more fallbacks, using output",
                    try_model,
                    q_reason,
                )
                if q_reason == "probe_target_out_of_scope":
                    cur = state.current_state.model_dump(mode="json")
                    clamped, creason = resolve_nmap_target(
                        decision.target,
                        state.target.strip(),
                        state.environment,
                        cur,
                    )
                    if decision.target.strip() != clamped.strip():
                        logger.info(
                            "Strategist clamped last-resort probe target %r -> %r (%s)",
                            decision.target,
                            clamped,
                            creason or "normalized",
                        )
                    decision = decision.model_copy(update={"target": clamped})

            if q_reason is None:
                if strategist_quality_enabled():
                    logger.info(
                        "Strategist quality OK model=%s action=%s (no escalation; same rules that drive fallback)",
                        try_model,
                        decision.action,
                    )
                else:
                    logger.debug(
                        "Strategist quality skipped model=%s action=%s (ADAPTIVE_SCAN_LLM_QUALITY off; no quality-based fallback)",
                        try_model,
                        decision.action,
                    )

            if try_model != self.model:
                logger.info(
                    "Strategist succeeded with fallback model %s (primary=%s)",
                    try_model,
                    self.model,
                )
            logger.debug(
                "Strategist OK model=%s action=%s target=%s phase=%s",
                try_model,
                decision.action,
                decision.target,
                decision.phase,
            )
            return decision

        logger.error("Strategist exhausted model chain %s", self._model_chain)
        if last_exc is not None:
            raise last_exc
        raise RuntimeError(f"strategist model chain empty: {self._model_chain!r}")

    def _ollama_generate_with_model(self, system: str, user: str, for_model: str) -> str:
        if _ollama_use_generate_api(for_model):
            logger.debug("Ollama strategist: POST /api/generate model=%s", for_model)
            return self._ollama_generate_via_generate(system, user, for_model)
        logger.debug("Ollama strategist: POST /api/chat model=%s", for_model)
        return self._ollama_generate_via_chat(system, user, for_model)

    def _ollama_generate_via_generate(self, system: str, user: str, for_model: str) -> str:
        prompt = (
            f"{system.strip()}\n\n"
            "======== SCAN STATE (your input) ========\n"
            f"{user.strip()}\n"
            "======== END STATE ========\n\n"
            "Respond with the strategist JSON object only (no markdown, no questions).\n"
        )
        body: dict[str, Any] = {
            "model": for_model,
            "prompt": prompt,
            "stream": False,
            "options": _ollama_options(for_model),
        }
        fmt = _ollama_format_field(for_model)
        if fmt is not None:
            body["format"] = fmt
        _apply_keep_alive(body)
        out = _ollama_post(self.base_url, "/api/generate", body, self.timeout_s)
        text = (out.get("response") or "").strip()
        if not text:
            raise ValueError(f"unexpected ollama /api/generate response: {out!r}")
        return text

    def _ollama_generate_via_chat(self, system: str, user: str, for_model: str) -> str:
        body: dict[str, Any] = {
            "model": for_model,
            "stream": False,
            "options": _ollama_options(for_model),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        think = _ollama_think_flag(for_model)
        if think is not None:
            body["think"] = think
        fmt = _ollama_format_field(for_model)
        if fmt is not None:
            body["format"] = fmt
        _apply_keep_alive(body)
        out = _ollama_post(self.base_url, "/api/chat", body, self.timeout_s)
        msg = out.get("message") or {}
        content = (msg.get("content") or out.get("response") or "").strip()
        thinking = (msg.get("thinking") or "").strip()
        if not content and thinking:
            content = thinking
        elif thinking and "{" not in content and "{" in thinking:
            content = thinking + "\n" + content
        if not content:
            raise ValueError(f"unexpected ollama /api/chat response: {out!r}")
        return content
