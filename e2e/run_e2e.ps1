# End-to-end lab from repo root (PowerShell). Requires Docker Compose v2.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Scale = if ($env:E2E_TARGET_SCALE) { $env:E2E_TARGET_SCALE } else { "30" }
$Subnet = if ($env:E2E_SCAN_TARGET) { $env:E2E_SCAN_TARGET } else { "172.30.0.0/24" }
$WaitSec = if ($env:E2E_START_WAIT) { [int]$env:E2E_START_WAIT } else { 15 }

function Get-E2EComposeArgs {
    $a = @(
        "compose", "--progress", "quiet",
        "-f", "e2e/docker-compose.yml"
    )
    if ($env:E2E_REAL_LLM -eq "1") {
        $a += @("-f", "e2e/docker-compose.ollama.yml")
    } else {
        $a += @("-f", "e2e/docker-compose.mock-llm.yml")
    }
    if ($env:E2E_INFRA -eq "1") {
        $a += @("-f", "e2e/docker-compose.infra.yml")
    }
    return $a
}

function Invoke-E2ECompose {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $base = Get-E2EComposeArgs
    docker @base @Args
}

if ($env:E2E_INFRA -eq "1") {
    if (-not $env:E2E_START_WAIT) { $WaitSec = 22 }
    Write-Host "Infra overlay enabled (LB @ 172.30.0.240, NAT edge @ 172.30.0.250:8080, firewalled-host)."
}

if ($env:E2E_REAL_LLM -eq "1") {
    Write-Host "Real Ollama LLM (e2e/docker-compose.ollama.yml); strategist calls hit a real model."
}

Write-Host "Building and starting stack (target scale=$Scale)..."
Invoke-E2ECompose @("up", "-d", "--build", "--scale", "target=$Scale")

try {
    if ($env:E2E_REAL_LLM -eq "1") {
        Write-Host "Waiting for Ollama API (up to 120s)..."
        $ready = $false
        for ($i = 0; $i -lt 120; $i++) {
            $base = Get-E2EComposeArgs
            docker @base @("exec", "-T", "ollama", "ollama", "list") 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $ready = $true
                break
            }
            Start-Sleep -Seconds 1
        }
        if (-not $ready) {
            throw "Ollama did not become ready in time."
        }
        # Match docker compose: repo-root .env for scanner; load OLLAMA_MODEL if shell var unset.
        if (-not $env:OLLAMA_MODEL -and (Test-Path ".env")) {
            $m = Select-String -Path ".env" -Pattern '^\s*OLLAMA_MODEL=' | Select-Object -First 1
            if ($m) {
                $env:OLLAMA_MODEL = ($m.Line -replace '^\s*OLLAMA_MODEL=', "").Trim().Trim('"').Trim("'")
            }
        }
        $model = if ($env:OLLAMA_MODEL) { $env:OLLAMA_MODEL } else { "qwen2.5-coder:1.5b" }
        if ($env:E2E_SKIP_OLLAMA_PULL -ne "1") {
            Write-Host "Pulling Ollama model $model (first run is large; E2E_SKIP_OLLAMA_PULL=1 to skip if volume already has it)..."
            Invoke-E2ECompose @("exec", "-T", "ollama", "ollama", "pull", $model)
        } else {
            Write-Host "Skipping ollama pull (E2E_SKIP_OLLAMA_PULL=1)."
        }
    }

    Write-Host "Waiting for targets (${WaitSec}s)..."
    Start-Sleep -Seconds $WaitSec

    Write-Host "Running scanner against $Subnet ..."
    Invoke-E2ECompose @("exec", "-T", "scanner", "python", "-m", "network_scanner", $Subnet, "--json-out", "/tmp/e2e_result.json", "-v")

    $base = Get-E2EComposeArgs
    $cid = (docker @base @("ps", "-q", "scanner") | Select-Object -First 1).Trim()
    docker cp "${cid}:/tmp/e2e_result.json" "e2e/last_e2e_result.json"
    Write-Host "Wrote e2e/last_e2e_result.json"
    python -c @"
import json
from pathlib import Path
p = Path('e2e/last_e2e_result.json')
d = json.loads(p.read_text(encoding='utf-8'))
fs = d.get('final_state') or {}
print('host_status:', fs.get('host_status'))
print('host_count:', fs.get('host_count'))
print('discovered_ports sample:', (fs.get('discovered_ports') or [])[:20])
ph = fs.get('per_host') or []
print('per_host rows:', len(ph))
"@
}
finally {
    Write-Host "Stopping stack..."
    Invoke-E2ECompose @("down", "--timeout", "2")
}
