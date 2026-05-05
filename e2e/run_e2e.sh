#!/usr/bin/env bash
# End-to-end lab: mock Ollama (fast) by default, or real Ollama (E2E_REAL_LLM=1 / run_e2e_real.sh).
# Optional: E2E_INFRA=1 adds LB, NAT-style port forward, firewalled host (see e2e/docker-compose.infra.yml).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Git Bash / MSYS2 rewrite /tmp/... to Windows Temp before docker.exe sees argv; the Linux
# container then gets C:/Users/.../Temp/... and FileNotFoundError on write.
export MSYS_NO_PATHCONV=1

_e2e_compose() {
  local args=(
    docker compose --progress quiet
    -f e2e/docker-compose.yml
  )
  if [[ "${E2E_REAL_LLM:-}" == "1" ]]; then
    args+=(-f e2e/docker-compose.ollama.yml)
  else
    args+=(-f e2e/docker-compose.mock-llm.yml)
  fi
  if [[ "${E2E_INFRA:-}" == "1" ]]; then
    args+=(-f e2e/docker-compose.infra.yml)
  fi
  "${args[@]}" "$@"
}

SCALE="${E2E_TARGET_SCALE:-30}"
SUBNET="${E2E_SCAN_TARGET:-172.30.0.0/24}"
WAIT_SEC="${E2E_START_WAIT:-15}"
if [[ "${E2E_INFRA:-}" == "1" ]]; then
  WAIT_SEC="${E2E_START_WAIT:-22}"
  echo "Infra overlay enabled (LB @ 172.30.0.240, NAT edge @ 172.30.0.250:8080, firewalled-host)."
fi

if [[ "${E2E_REAL_LLM:-}" == "1" ]]; then
  echo "Real Ollama LLM (e2e/docker-compose.ollama.yml); strategist calls hit a real model."
fi

echo "Building and starting stack (target scale=$SCALE)..."
_e2e_compose up -d --build --scale "target=$SCALE"

cleanup() {
  echo "Stopping stack..."
  _e2e_compose down --timeout 2
}
trap cleanup EXIT

if [[ "${E2E_REAL_LLM:-}" == "1" ]]; then
  echo "Waiting for Ollama API (up to 120s)..."
  _ok=
  for _ in $(seq 1 120); do
    if _e2e_compose exec -T ollama ollama list >/dev/null 2>&1; then
      _ok=1
      break
    fi
    sleep 1
  done
  if [[ -z "${_ok:-}" ]]; then
    echo "ERROR: Ollama did not become ready in time." >&2
    exit 1
  fi
  # Compose loads repo-root .env for the scanner; source it here too so ollama pull matches.
  if [[ -z "${OLLAMA_MODEL:-}" ]] && [[ -f .env ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
  fi
  MODEL="${OLLAMA_MODEL:-qwen2.5-coder:1.5b}"
  if [[ "${E2E_SKIP_OLLAMA_PULL:-}" != "1" ]]; then
    echo "Pulling Ollama model ${MODEL} (first run is large; E2E_SKIP_OLLAMA_PULL=1 to skip if volume already has it)..."
    _e2e_compose exec -T ollama ollama pull "$MODEL"
  else
    echo "Skipping ollama pull (E2E_SKIP_OLLAMA_PULL=1)."
  fi
fi

echo "Waiting for targets (${WAIT_SEC}s)..."
sleep "$WAIT_SEC"

echo "Running scanner against $SUBNET ..."
_e2e_compose exec -T scanner \
  python -m network_scanner "$SUBNET" --json-out /tmp/e2e_result.json -v

echo "Copying result out of container..."
CID="$(_e2e_compose ps -q scanner | head -1)"
docker cp "$CID:/tmp/e2e_result.json" e2e/last_e2e_result.json

echo "Wrote e2e/last_e2e_result.json"
python - <<'PY'
import json
from pathlib import Path
p = Path("e2e/last_e2e_result.json")
d = json.loads(p.read_text(encoding="utf-8"))
fs = d.get("final_state") or {}
print("host_status:", fs.get("host_status"))
print("host_count:", fs.get("host_count"))
print("discovered_ports sample:", (fs.get("discovered_ports") or [])[:20])
ph = fs.get("per_host") or []
print("per_host rows:", len(ph))
PY

trap - EXIT
cleanup
