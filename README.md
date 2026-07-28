# Adaptive network scanner

LLM guided (Qwen coder and Gemma via Ollama) Nmap orchestration. It is capable of discovering enterprise networks with a single command from a regular PC without a powerful GPU. Low noise mode offers low visibility (though it will not reliably defeat a strong firewall or hide from EDR)


## Installation and Usage

```bash
pip install -r requirements.txt
python -m network_scanner 192.0.2.10
python -m network_scanner 10.0.0.0/24 --json-out out.json
```
**Requires a running Ollama** (or compatible API at `OLLAMA_HOST`(see below)) and a model (`OLLAMA_MODEL`(see below)). The code default is **`gemma4:e2b`**; for **low RAM / speed**, try **`qwen2.5-coder:1.5b`** or **`qwen2.5-coder:0.5b`**.

## Configuration

The scanner has a "strategist" as an LLM that acts as a decision taker, and an "orchestrator" for loop and execution management. Advanced behavior is configured with `ADAPTIVE_SCAN_*` environment variables rather than CLI flags.


| Variable | Purpose |
|----------|---------|
| `OLLAMA_HOST`, `OLLAMA_MODEL` | Ollama host and primary strategist model (required) |
| `ADAPTIVE_SCAN_LLM_FALLBACK` | Comma-separated extra Ollama model tags. On **JSON parse**, **pydantic**, **invalid action**, **Ollama HTTP / connection** failure, or **quality heuristics** (see below), the strategist **retries** the same step with the next model (primary = `OLLAMA_MODEL` first). Empty = no fallback. **No spaces after commas** (or wrap the whole value in **double quotes**), or **`source .env`** may treat `tag:variant` as a command. |
| `ADAPTIVE_SCAN_LLM_QUALITY` | `1` (default): enable **strategist_quality** checks so useless outputs can trigger the fallback chain (evasion stalls, premature `stop_scan`, **probe target outside session CIDR** / scope, …). `0` / `false` / `off` disables. |
| `ADAPTIVE_SCAN_LLM_STALL_THRESHOLD` | Consecutive completed steps **without** an executed nmap/probe (from history `_resolved_action`) while **no probe has run yet**, plus the current decision if it would not run a probe (`repeat_last_action` that would run nmap counts as a probe). Mostly evasion-only loops; alternating evasion with fragmentation/decoys no longer resets the count. Log reason: `pre_nmap_stall>=N`. Default **`3`**. |
| `ADAPTIVE_SCAN_LLM_POST_SCAN_STALL_THRESHOLD` | After at least one probe, **still no discovery signal** (host unknown, no ports/hosts): same evasion-only streak as above triggers fallback at this count. **Unset** → use the same integer as **`ADAPTIVE_SCAN_LLM_STALL_THRESHOLD`** (default 3). Set **`0`** / **`off`** / **`false`** / **`no`** / **`none`** to **disable** this rule only (pre-nmap stall unchanged). |
| `ADAPTIVE_SCAN_OLLAMA_KEEP_ALIVE` | Optional Ollama **`keep_alive`** on each strategist request (e.g. **`0`** to unload the model after the call — slower when switching models, lower peak RAM). |
| `ADAPTIVE_SCAN_MAX_STEPS` | Strategist iterations (default 25) |
| `ADAPTIVE_SCAN_DB` | SQLite path |
| `ADAPTIVE_SCAN_RESUME` | Session UUID to continue |
| `ADAPTIVE_SCAN_SESSION_ID` | Fixed session id for a new run |
| `ADAPTIVE_SCAN_VERSION_INTENSITY` | Override `-sV` intensity (all service/banner/tls actions using `-sV`) |
| `ADAPTIVE_SCAN_GLOBAL_MAX_SCAN_RATE` | `--max-scan-rate` on every run when set |
| `ADAPTIVE_SCAN_XDR_MAX_SCAN_RATE` | Extra cap when low-noise / XDR path |
| `ADAPTIVE_SCAN_SCAN_DELAY` | e.g. `300ms` |
| `ADAPTIVE_SCAN_NMAP_EXTRA` | Extra Nmap args (quoted shell tokens) |
| `ADAPTIVE_SCAN_NMAP_TIMEOUT` | Seconds for the **Python subprocess** around each nmap run (default **600**). If this is **less** than the time nmap needs (e.g. **`/24`** + **`large_network`** + large **`--host-timeout`**), the process is killed (**exit 124**, anomaly **`nmap_timeout`**). Logs: **`nmap start … ADAPTIVE_SCAN_NMAP_TIMEOUT=…`** and **`nmap killed by subprocess timeout`**. |
| `ADAPTIVE_SCAN_CACHE_TTL` | Seconds; or `--cache-ttl-seconds` |
| `ADAPTIVE_SCAN_EXCLUDE_PORTS` | nmap `--exclude-ports` (spaces stripped) |
| `ADAPTIVE_SCAN_IPV6` | `1`/`true`/`yes` → nmap `-6` |
| `ADAPTIVE_SCAN_CHUNK_IPV4_PREFIX` | Split IPv4 CIDR into `/N` chunks (integer) |
| `ADAPTIVE_SCAN_PROFILE` | JSON file path overlay on `Environment` |
| `ADAPTIVE_SCAN_MERGE_STATE` | Path to prior `--json-out` to merge |
| `ADAPTIVE_SCAN_MERGE_PEER_ID` | Label for merged peer |
| `ADAPTIVE_SCAN_SEED_HOSTS_FILE` | One host/IP per line |
| `ADAPTIVE_SCAN_TOPOLOGY_JSON` | Topology / indirect hints JSON |
| `ADAPTIVE_SCAN_PASSIVE_ARP` | `1` = harvest local ARP/neighbors |
| `ADAPTIVE_SCAN_SCANNER_ID` | Label for multi-vantage merges |
| `ADAPTIVE_SCAN_RESUME_ENV` | `checkpoint` (default) or `cli` |
| `ADAPTIVE_SCAN_NO_PERSIST_CONNECT` | `1` = do not lock in `-sT` after SYN privilege failure |
| `ADAPTIVE_SCAN_LLM_MAX_HOSTS` | Cap hosts sent to the LLM |
| `ADAPTIVE_SCAN_LLM_RECENT_STEPS` | How many completed steps to summarize in `recent_steps` for the strategist (default `5`, max `24`; `0` disables) |
| `ADAPTIVE_SCAN_RELOAD_SEEDS_INTERVAL` | Re-read seed file every N seconds |
| `ADAPTIVE_SCAN_RELOAD_SEEDS_MTIME` | `1` = re-read when seed file mtime changes |
| `ADAPTIVE_SCAN_DRY_RUN` | `1` = print first nmap argv only |
| `ADAPTIVE_SCAN_UDP_TOP_PORTS` | String count for `nmap_udp_scan` `--top-ports` (overrides defaults) |
| `ADAPTIVE_SCAN_LLM_TUNING` | `0` / `off` disables strategist `run_tuning` (default **on** when unset); clamps use the variables above |
| `ADAPTIVE_SCAN_REPEAT_GUARD` | `0` / `off` disables automatic remap when the model repeats the same nmap action on the same target as the prior step (default **on** when unset) |
---
