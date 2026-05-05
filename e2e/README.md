# End-to-end virtual lab

This directory defines a **large Layer-3 lab** with Docker Compose: many Python `http.server` containers on **`172.30.0.0/24`**, while the **scanner** and **LLM endpoint** sit on a separate control network (**`172.31.0.0/28`**). That keeps Ollama/mock traffic off the scan subnet and mimics a fat target network.

## Git Bash on Windows

If you use **Git Bash**, MSYS turns paths like `/tmp/e2e_result.json` into **`C:/Users/.../AppData/Local/Temp/...`** before `docker.exe` runs, so the **Linux** scanner container tries to open a Windows path and fails. **`run_e2e.sh`** sets **`MSYS_NO_PATHCONV=1`** to stop that. If you run `docker compose exec ...` by hand, prefix with the same or use **`run_e2e.ps1`**.

## Quick path (mock “Ollama”, fast CI / laptops)

Uses a tiny HTTP server that speaks **`POST /api/chat`** like Ollama and returns a fixed sequence of strategist JSON decisions (`mock_decisions.jsonl`). **Real nmap** runs inside the scanner container against the real container IPs.

From the **repository root**:

```bash
chmod +x e2e/run_e2e.sh   # Unix
./e2e/run_e2e.sh
```

**Windows:** Do **not** run `./e2e/run_e2e.sh` from PowerShell alone (it will not execute bash; you may see no output). Use one of:

```powershell
.\e2e\run_e2e.ps1
```

Or double-click / run **`e2e\run_e2e.cmd`** (requires **Git Bash** `bash` on `PATH`). Or from **Git Bash**: `./e2e/run_e2e.sh`.

The `(node:...) punycode` message comes from the **Cursor/VS Code** shell host, not this repo.

**Scanner container env:** edit **`.env` at the repository root** only. Compose loads it via **`env_file: ../.env`** from **`e2e/docker-compose.yml`**. The **real-Ollama** and **mock-LLM** overlays set only **`OLLAMA_HOST`** (and **`OLLAMA_MODEL=mock`** for mock); everything else (**`OLLAMA_MODEL`**, **`OLLAMA_TIMEOUT`**, **`ADAPTIVE_SCAN_*`**, …) comes from **`.env`**.

**Empty scan / `nmap_timeout` in `last_e2e_result.json`:** often **`ADAPTIVE_SCAN_NMAP_TIMEOUT`** (Python subprocess cap) is **shorter** than the time nmap needs for **`172.30.0.0/24`** with **`large_network`** and LLM **`--host-timeout`**. Logs now print **`nmap start … ADAPTIVE_SCAN_NMAP_TIMEOUT=…`** and **`nmap killed by subprocess timeout`** when that happens. Raise **`ADAPTIVE_SCAN_NMAP_TIMEOUT`** in repo-root **`.env`** (e.g. **`600`**) or increase **`E2E_START_WAIT`** if targets are still booting.

Environment knobs:

| Variable | Default | Meaning |
|----------|---------|---------|
| `E2E_TARGET_SCALE` | `30` | `docker compose --scale target=N` |
| `E2E_SCAN_TARGET` | `172.30.0.0/24` | CIDR passed to `python -m network_scanner` |
| `E2E_INFRA` | unset | Set to `1` to merge **`docker-compose.infra.yml`**: load balancer, NAT-style port forward, firewalled host |
| `E2E_START_WAIT` | `15` (or `22` with infra) | Seconds to sleep after `up` (and after Ollama pull, if real LLM) before scanning |
| `E2E_REAL_LLM` | unset | Set to `1` to use **`docker-compose.ollama.yml`** (real **Ollama** + model) instead of the mock server. Or run **`e2e/run_e2e_real.sh`** / **`run_e2e_real.ps1`** / **`run_e2e_real.cmd`**. |
| `E2E_SKIP_OLLAMA_PULL` | unset | With real LLM: set to `1` to skip **`ollama pull`** when the **`ollama_e2e`** volume already has **`OLLAMA_MODEL`**. |
| `OLLAMA_MODEL` | see **`.env`** | Model tag for the real-LLM stack. **`run_e2e.sh`** / **`run_e2e.ps1`** read **`.env`** at repo root when `OLLAMA_MODEL` is unset in the shell, so **`ollama pull`** matches the scanner. Override per run: `OLLAMA_MODEL=gemma4:e2b ./e2e/run_e2e_real.sh`. **Lighter/faster:** `qwen2.5-coder:0.5b`. **Heavier:** `gemma4:e2b`. Official [qwen3-coder](https://ollama.com/library/qwen3-coder) is **30B / 480B** only; sub-2B “coder” models use **`qwen2.5-coder`** tags (e.g. |
| `OLLAMA_OPTIONS` | unset | JSON object merged into Ollama **`options`** (e.g. **`{"num_gpu":0}`** for CPU-only). Set in repo-root **`.env`**. |
| `ADAPTIVE_SCAN_LLM_FALLBACK` | unset | Comma-separated model tags; strategist **retries** the same step on parse/validation/Ollama errors **or quality heuristics** (see root **`README.md`**). Set in repo-root **`.env`** or shell. |
| `ADAPTIVE_SCAN_OLLAMA_KEEP_ALIVE` | unset | Optional; e.g. **`0`** to unload the model after each strategist call (slower, less RAM when switching). |
| `OLLAMA_TIMEOUT` | **`600`** in **`.env`** | HTTP client timeout (seconds) per strategist call (**`/api/generate`** or **`/api/chat`**). Raise for **Gemma 4** on CPU or slow first load; small **Qwen2.5-coder** is usually quicker. |
| `OLLAMA_THINK` | unset | **`true`** / **`false`** forces Ollama **`think`**; unset omits the field (Ollama default). |
| `OLLAMA_CHAT_FORMAT` | unset | **`gemma4*`:** client sends **JSON Schema** `format` by default. **`qwen2.5-coder` / `qwen2.5*`:** default **`format: json`** (loose) when unset. Set **`schema`** to force JSON Schema on any model, **`none`** / **`0`** / **`off`** to omit `format`. |
| `OLLAMA_USE_GENERATE_API` | unset | **`gemma4*`** uses **`POST /api/generate`** (avoids chatty chat templates). Set **`0`** / **`false`** / **`chat`** to force **`/api/chat`**. Set **`1`** / **`generate`** to force generate for any model. |

### Optional infra overlay (LB, “NAT”, firewall)

With **`E2E_INFRA=1`**, the runners add **`-f e2e/docker-compose.infra.yml`**. That brings:

- **Load balancer:** nginx at **`172.30.0.240`**, fronting three backends (`lb-back-1` … `3`) on port 80.
- **NAT-style edge:** **`172.30.0.250:8080`** forwards to **`internal-web:80`**, which lives only on private **`10.10.0.0/24`** (not on the scan subnet). This simulates **port forwarding** / “reach internal service via a public IP,” not full iptables SNAT/DNAT.
- **Firewalled host:** a container with **iptables** rejecting **TCP/80** while **HTTP on 8080** still works (needs **`NET_ADMIN`**; may be a no-op on some hosts—in that case only **8080** is interesting).

**IP collision:** static addresses **`.240`** and **`.250`** are reserved. If you scale **`target`** high enough that Compose assigns those IPs to scaled replicas, move the static IPs in **`docker-compose.infra.yml`** or lower scale.

**VPN:** not automated in compose (keys, TUN, `privileged`). See **`e2e/infra/VPN.md`** for a sketch.

```bash
E2E_INFRA=1 ./e2e/run_e2e.sh
```

Manual compose (mock stack + infra):

```bash
docker compose -f e2e/docker-compose.yml -f e2e/docker-compose.mock-llm.yml \
  -f e2e/docker-compose.infra.yml up -d --build --scale target=30
```

Artifacts: **`e2e/last_e2e_result.json`** (copied out of the scanner container after the run).

Manual equivalent:

```bash
docker compose -f e2e/docker-compose.yml -f e2e/docker-compose.mock-llm.yml up -d --build --scale target=50
# wait for targets
docker compose -f e2e/docker-compose.yml -f e2e/docker-compose.mock-llm.yml exec scanner \
  python -m network_scanner 172.30.0.0/24 --json-out /tmp/out.json
docker compose -f e2e/docker-compose.yml -f e2e/docker-compose.mock-llm.yml down
```

The mock stack sets **`ADAPTIVE_SCAN_LLM_TUNING=0`** so only scripted actions apply (still requires a working `/api/chat`).

## Real LLM e2e (Ollama)

This is the **full** path: **real nmap** plus a **real** strategist model via **`ollama/ollama`** (not `mock_ollama_server.py`). First run downloads **`OLLAMA_MODEL`** (default **`qwen2.5-coder:1.5b`**, ~1GB — [library/tags](https://ollama.com/library/qwen2.5-coder/tags)) into the **`ollama_e2e`** volume; later runs reuse it.

**Speed vs RAM:** Smaller weights are **usually faster** and use **less** RAM/VRAM (e.g. **`qwen2.5-coder:0.5b`** ~400MB is quicker/lighter than **1.5b**, with **more** JSON / instruction drift — runtime **target clamping** still keeps nmap on the session CIDR). **Gemma 4** (`gemma4:e2b`, ~7GB+) is heavier and slower on CPU but can follow structure better; set **`OLLAMA_MODEL`** accordingly.

**Note:** [qwen3-coder](https://ollama.com/library/qwen3-coder) on Ollama is **30B / 480B** only; there is no official **0.8B / 1.7B** `qwen3-coder` tag — use **`qwen2.5-coder`** for small coder models.

CPU-only is slow but works; GPU depends on your Docker setup.

```bash
./e2e/run_e2e_real.sh
```

```powershell
.\e2e\run_e2e_real.ps1
```

Or equivalently: **`E2E_REAL_LLM=1 ./e2e/run_e2e.sh`**. Combine with infra: **`E2E_REAL_LLM=1 E2E_INFRA=1 ./e2e/run_e2e.sh`**.

After the stack is healthy, the script waits for **`ollama list`**, runs **`ollama pull`** unless **`E2E_SKIP_OLLAMA_PULL=1`**, waits **`E2E_START_WAIT`**, then runs the scanner (same **`e2e/last_e2e_result.json`** artifact as the mock path).

**CI:** real LLM e2e is usually **opt-in** (large image, pull time, non-deterministic outputs). Keep the **mock** path as the default fast gate.

**Manual compose** (same files the script merges):

```bash
docker compose -f e2e/docker-compose.yml -f e2e/docker-compose.ollama.yml up -d --build --scale target=20
docker compose -f e2e/docker-compose.yml -f e2e/docker-compose.ollama.yml exec ollama ollama pull qwen2.5-coder:1.5b
# then exec scanner as in the “Manual equivalent” section above, with these compose files
```

### If Ollama returns HTTP 500 (or hangs)

The scanner now raises with the **Ollama response body** in the message (not just “500 Internal Server Error”). Still useful:

1. **`docker compose ... logs ollama`** (same compose files as the run) for the runner crash / CUDA line.
2. **Gemma 4** needs **Ollama ≥ 0.20**: `docker compose ... exec ollama ollama --version`.
3. The **`ollama`** service sets **`OLLAMA_NUM_PARALLEL=1`** in **`docker-compose.ollama.yml`** to avoid some parallel GPU bugs.
4. **CPU-only inference** (workaround for bad GPU drivers on Docker Desktop): set on the **scanner** env  
   **`OLLAMA_OPTIONS='{"num_gpu":0}'`** (JSON merged into Ollama request `options`).
5. Strategist **`format`**: **JSON Schema** for **`gemma4*`** by default; **`format: json`** for **`qwen2.5*`** when unset. Override with **`OLLAMA_CHAT_FORMAT`**. **`think`** is omitted by default.

## Mininet (optional, Linux + privileged)

Docker Compose is the **supported** way to get “many hosts” without special kernels. **Mininet** can emulate larger or stranger L2 topologies but usually needs:

- Linux host or Linux VM
- **`docker run --privileged`** (or bare-metal Mininet)
- Extra routing between the Mininet data plane and where you run **nmap**

If you need Mininet specifically (e.g. SDN switches, custom latency), start from [Mininet](https://github.com/mininet/mininet) docs and run **nmap from a host that has L3 reachability** into the Mininet address space; wire the scanner container or binary accordingly. A starter sketch lives under **`e2e/mininet/`**.

## Teardown noise / slowness

With many scaled targets, plain `docker compose down` can print **hundreds of repeated “Stopping” lines** and wait up to the **default 10s stop grace** per wave. The bundled **`run_e2e.sh` / `run_e2e.ps1`** use **`--progress quiet`**, **`down --timeout 2`**, and compose **`stop_grace_period: 2s`** so shutdown stays short and readable. For manual runs:

`docker compose --progress quiet -f e2e/docker-compose.yml -f e2e/docker-compose.mock-llm.yml down --timeout 2`

## Requirements

- Docker Compose **v2** (supports `--progress quiet` and `--timeout` on `down`)
- Enough RAM/CPU for **`E2E_TARGET_SCALE`** tiny Python servers (dozens to low hundreds is typical on a dev machine)
- **nmap** inside the scanner image (installed in `Dockerfile.scanner`)

## CI

Run **`./e2e/run_e2e.sh`** (or the compose commands) in a job with Docker-in-Docker; keep **`E2E_TARGET_SCALE`** modest (e.g. `15`) for speed. Use the **mock** overlay unless the runner can cache Ollama models.
