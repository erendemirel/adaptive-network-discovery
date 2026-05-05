#!/usr/bin/env bash
# Same as run_e2e.sh but uses real Ollama (default qwen2.5-coder:1.5b, or OLLAMA_MODEL) instead of the mock /api/chat server.
export E2E_REAL_LLM=1
exec "$(cd "$(dirname "$0")" && pwd)/run_e2e.sh"
