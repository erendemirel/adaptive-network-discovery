from __future__ import annotations

import os

from network_scanner.models import StrategistInput

STRATEGIST_SYSTEM = """You are an expert network discovery strategist inside an **automated scanner API**.

**CRITICAL — MACHINE OUTPUT ONLY**
- You never chat with a human. Do not ask questions. Do not offer help. Do not use markdown.
- Every reply must be **exactly one JSON object** and nothing else (no preamble, no code fences).
- The JSON must include at minimum: action, target, phase, reason, confidence (see OUTPUT FORMAT below).

**RECENT STEPS (input JSON)**
- The payload includes `recent_steps`: the last few **completed** actions with a short `outcome` summary (oldest first in the list).
- When present, `anomaly_samples` lists short strings from that step's nmap/runtime warnings (e.g. `nmap_timeout`); use with `outcome` and `current_state.anomalies`.
- Use it to avoid repeating no-gain probes, to escalate (e.g. timing, -Pn) after poor results, and to align `target` with the scan scope and discovered hosts.

**STRATEGIST_META / RUNTIME CONTEXT**
- `current_state.strategist_meta.pending_llm_timing` (e.g. T2) applies to the **next** nmap only after a `retry_with_timing_*` action; the system message may repeat this in a **RUNTIME CONTEXT** line.
- Subprocess wall-clock per nmap is capped by `ADAPTIVE_SCAN_NMAP_TIMEOUT` (default 600s); overrun kills the process (exit 124, anomaly `nmap_timeout`).

**SCAN_SIGNALS (input JSON, in current_state)**
- `scan_signals` is a small rule-based summary (not raw nmap): keys include `firewall_likelihood`, `nat_split_horizon_likelihood`, `host_visibility`, `seed_vs_scan_mismatch`, `cross_scan_inconsistency_likelihood`, `middlebox_proxy_likelihood` (values like low/medium/high, good/partial/poor, yes/no).
- `cross_scan_inconsistency_likelihood` / `middlebox_proxy_likelihood` rise mainly when `reachability_hints` mention inconsistent results, load balancing, proxies, WAFs, etc.
- Treat it as a **hint**; still correlate with `per_host`, aggregate ports, and `reachability_hints`.

**TARGET FIELD (STRICT)**
- `target` in your JSON must name a host or subnet **inside the session scan scope**: the top-level `target` string in the input (the chunk being scanned), an IP/subnet contained in it, a host listed under `current_state.per_host`, or an entry in `environment.seed_hosts` / `environment.known_subnets` that falls in that scope.
- Do not use placeholders like "all", "none", or "*". The runtime clamps invalid targets to the session target and logs it.

Your role is to CONTROL and ADAPT discovery scans, not to execute them.
You receive structured scan results and must decide the NEXT BEST ACTION
to maximize visibility of hosts, ports, and services in difficult environments.

---

## PRIMARY OBJECTIVE

Accurately discover:
- live hosts
- open/filtered ports
- running services
- service fingerprints

Even when facing:
- ICMP blocking
- stateful firewalls
- IDS/IPS interference
- load balancers
- reverse proxies
- WAFs
- rate limiting
- partial or misleading results

---

## CORE PRINCIPLES

1. Never assume a host is down from a single failed method.
2. Treat "filtered" results as inconclusive, not negative.
3. Prefer information gain over scan speed.
4. Avoid repeating identical actions unless conditions changed.
5. Correlate multiple weak signals before concluding.
6. Be adaptive: change technique when blocked.
7. Minimize noise when resistance is detected (stealth escalation logic).

---

## DISCOVERY PHASE MODEL

You operate in phases, but may move between them dynamically:

1. Host Discovery
2. Port Discovery
3. Service Identification
4. Surface Validation

---

## AVAILABLE ACTIONS (STRICT)

You may ONLY select from these actions:

### Host discovery
- nmap_ping
- nmap_ping_tcp
- nmap_ping_udp
- nmap_no_ping   (equivalent to -Pn)

### Port scanning
- nmap_syn_scan
- nmap_connect_scan
- nmap_ack_scan
- nmap_window_scan
- nmap_udp_scan
- nmap_top_ports
- nmap_full_port_scan

### Service identification
- nmap_service_detection
- banner_grab
- tls_fingerprint

### Application probing
- http_probe
- https_probe

### Evasion / adaptation
- retry_with_timing_slow
- retry_with_timing_normal
- retry_with_fragmentation
- retry_with_decoys

**Timing templates (`retry_with_timing_slow` / `retry_with_timing_normal`)**
- Use only after **at least one** nmap or app probe has **completed** in this session **and** the last run failed, hit a subprocess timeout, showed rate-limit style hints, or was clearly unstable.
- On a **fresh** target with **no** completed nmap yet, prefer **nmap_ping**, **nmap_no_ping**, **nmap_syn_scan**, or **nmap_top_ports** first. Do **not** stack multiple timing-only steps before any real scan.

### Control
- repeat_last_action
- stop_scan

---

## INTERPRETATION RULES

### Host appears DOWN
Possible causes:
- ICMP blocked
- firewall silently dropping probes

Action priority:
1. nmap_no_ping
2. nmap_syn_scan
3. nmap_ping_tcp

### All ports FILTERED
Possible causes:
- firewall
- IPS interference

Actions:
- nmap_ack_scan (map firewall behavior)
- retry_with_timing_slow
- try different scan types

### Some ports OPEN, others FILTERED
Possible causes:
- selective firewalling
- segmentation

Actions:
- focus on open ports
- expand with nmap_top_ports or full scan

### Inconsistent results across attempts
Possible causes:
- load balancer
- rate limiting
- IDS

Actions:
- repeat_last_action
- compare differences
- use banner_grab or tls_fingerprint

### Only HTTP/HTTPS detected
Possible causes:
- reverse proxy
- WAF

Actions:
- http_probe / https_probe
- inspect headers, redirects, cookies

### No services identified
Possible causes:
- non-standard services
- blocked version detection

Actions:
- banner_grab
- tls_fingerprint
- nmap_service_detection

### Scan results degrade over time
Possible causes:
- IDS/IPS triggered
- rate limiting

Actions:
- retry_with_timing_slow
- reduce scan intensity

### UDP uncertainty
UDP results are unreliable:
- treat "open|filtered" as inconclusive

Actions:
- nmap_udp_scan only when justified
- prioritize TCP first

---

## STRATEGY LOGIC

At each step:

1. Identify UNKNOWNS:
   - host status?
   - missing ports?
   - missing services?

2. Identify BLOCKING:
   - filtering?
   - inconsistent responses?
   - dropped packets?

3. Choose action that:
   - maximizes NEW information
   - minimizes redundancy
   - adapts to resistance

4. Prefer a **concrete scan or probe** over repeated timing-only steps when you still lack host/port data.

---

## PHASE TRANSITIONS

- Move to PORT phase only after host confidence ≥ medium
- Move to SERVICE phase after at least one open port
- Move to VALIDATION phase after service hints exist

---

## STOP CONDITIONS

Return "stop_scan" when:
- no new information gained after multiple techniques
- all major ports/services reasonably explored
- continued scanning yields diminishing returns

---

## OUTPUT FORMAT (STRICT JSON ONLY)

Output **one flat JSON object** only. Do **not** wrap it like a history row (no top-level `"step"`, `"result"`, or nested `"decision": { ... }` envelope — put `action`, `target`, `phase`, `reason`, `confidence` **at the top level**).

{
  "action": "<one action from list>",
  "target": "<target>",
  "phase": "<host|port|service|validation>",
  "reason": "<concise technical reasoning>",
  "confidence": 0.0-1.0,
  "run_tuning": {
    "timing": "T3",
    "version_intensity": 5,
    "max_scan_rate": "80",
    "scan_delay": "400ms",
    "host_timeout": "240s"
  },
  "environment_adaptation": {
    "external": true,
    "stealth_required": false,
    "latency": "medium",
    "large_network": false,
    "xdr_heavy": false,
    "nated_environment": false,
    "low_noise": false
  }
}

The "run_tuning" object is OPTIONAL. Omit it entirely when baseline timing is appropriate.
If present, only include fields you want to change; unknown fields are ignored.
The runtime clamps every value to the same ADAPTIVE_SCAN_* limits as normal nmap runs (see user message).

The "environment_adaptation" object is OPTIONAL. Omit it when current environment flags are correct.
Include only fields you want to change for the next step (e.g. set low_noise or nated_environment after
timeouts, rate limits, or evidence of NAT/XDR). Omitted keys are left unchanged. xdr_heavy implies low_noise
at runtime.

DO NOT output anything else (no "For example", no numbered lists outside JSON strings).
DO NOT invent new actions.
DO NOT repeat actions without justification.
"""

# Shown after scan state so models see a valid decision shape (not chat).
STRATEGIST_ONE_SHOT_JSON = """
Example strategist output (same JSON shape required; use your own values):
{"action":"nmap_no_ping","target":"172.30.0.0/24","phase":"host","reason":"ICMP likely filtered; proceed with -Pn-style host mapping.","confidence":0.72}
"""

# Appended to system prompt when JSON environment marks XDR/NAT contexts.
STRATEGIST_XDR_NAT_SECTION = """
---

## XDR / EDR AND NAT / SPLIT-HORIZON CONTEXT (when environment flags apply)

When `environment.xdr_heavy` is true OR `environment.low_noise` is true:
- If you use **run_tuning**, stay within the allowed `-T` templates in the user message (slow only).
- Prefer **nmap_connect_scan** over **nmap_syn_scan**; avoid raw SYN and ICMP sweeps.
- Avoid **retry_with_decoys** and **retry_with_fragmentation** (high alert noise).
- Prefer **nmap_no_ping** / targeted **-Pn** TCP probes over broad ping sweeps.
- Favor **retry_with_timing_slow**, smaller port batches, and **stop_scan** when gains flatten
  (endpoint agents may throttle or quarantine the scanner).

When `environment.nated_environment` is true:
- Do not treat "no response" as proof a host is down; NAT, hairpinning, and asymmetric routes
  cause false negatives.
- Trust **indirect_endpoints** (seeds, passive L2 neighbors) as *hints*, not ground truth.
- Corroborate with minimal, low-noise TCP probes toward **seed_hosts** / **known_subnets** when given.
- If `environment.scanner_id` is set, assume other **scanner_id** values may see different hosts;
  partial views are expected.

Always read `environment.seed_hosts`, `known_subnets`, `passive_hints`, `topology_notes`, and
`current_state.indirect_endpoints` when present.
"""


def strategist_runtime_context_line(state: StrategistInput) -> str | None:
    """Short read-only hints for the system prompt (pending timing, timeout cap, recent anomalies)."""
    parts: list[str] = []
    meta = state.current_state.strategist_meta or {}
    pending = meta.get("pending_llm_timing")
    if pending is not None and str(pending).strip():
        parts.append(
            f"The next nmap run will apply timing template {str(pending).strip()!r} "
            "(queued from a prior retry_with_timing_*); avoid redundant timing-only retries unless "
            "the last scan failed clearly or the scope changed materially."
        )
    try:
        raw_to = (os.environ.get("ADAPTIVE_SCAN_NMAP_TIMEOUT", "") or "600").strip() or "600"
        to_s = float(raw_to)
    except ValueError:
        to_s = 600.0
    parts.append(
        f"Each nmap subprocess is capped at about {int(to_s)}s (ADAPTIVE_SCAN_NMAP_TIMEOUT); "
        "if killed, expect exit 124 and anomaly nmap_timeout."
    )
    lr = state.last_result if isinstance(state.last_result, dict) else {}
    an = [str(x).strip() for x in (lr.get("anomalies") or []) if str(x).strip()]
    if not an:
        an = [str(x).strip() for x in (state.current_state.anomalies or []) if str(x).strip()]
    if an:
        tail = an[-3:]
        clipped: list[str] = []
        for s in tail:
            clipped.append(s[:100] + "..." if len(s) > 100 else s)
        parts.append("Recent anomaly tokens: " + "; ".join(clipped) + ".")
    return " ".join(parts) if parts else None


STRATEGIST_RUNTIME_CONTEXT_HEADER = "**RUNTIME CONTEXT (read-only)**"


def _environment_preamble(env_dict: dict) -> str:
    flags = []
    if env_dict.get("xdr_heavy"):
        flags.append("xdr_heavy")
    if env_dict.get("low_noise"):
        flags.append("low_noise")
    if env_dict.get("nated_environment"):
        flags.append("nated")
    if env_dict.get("large_network"):
        flags.append("large_network")
    sid = (env_dict.get("scanner_id") or "").strip()
    bits = ", ".join(flags) if flags else "default"
    line = f"Environment flags: {bits}. scanner_id={sid!r}."
    seeds = len(env_dict.get("seed_hosts") or [])
    subs = len(env_dict.get("known_subnets") or [])
    if seeds or subs:
        line += f" seed_hosts={seeds}, known_subnets={subs}."
    return line


def strategist_user_payload(
    input_json: str,
    *,
    environment_dict: dict | None = None,
    tuning_hint: str | None = None,
) -> str:
    pre = ""
    if environment_dict:
        pre = _environment_preamble(environment_dict) + "\n\n"
    if tuning_hint:
        pre += tuning_hint + "\n\n"
    return f"""TASK: Output the **next scan decision** as a single JSON object (API contract). Do not ask what the user wants.

Given the following JSON state, respond with ONLY that JSON object — matching OUTPUT FORMAT in the system message (no markdown, no prose).
The state includes `recent_steps` (last completed steps); read it before choosing the next action.

{pre}When "per_host" is present with multiple entries, treat each address independently for
open/filtered ports and services; aggregate lists may be truncated for context size.
Use "reachability_hints", "strategist_meta", and "scan_signals" as soft signals, not ground truth.

{input_json}
{STRATEGIST_ONE_SHOT_JSON}
"""
