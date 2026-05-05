# Real-LLM e2e: Ollama in Docker pulls/runs the strategist model (slow first run).
$env:E2E_REAL_LLM = "1"
& (Join-Path $PSScriptRoot "run_e2e.ps1")
