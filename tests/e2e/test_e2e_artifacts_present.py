"""Sanity check that the Docker e2e stack files exist (no Docker run)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
E2E = ROOT / "e2e"


def test_e2e_compose_files_exist():
    assert (E2E / "docker-compose.yml").is_file()
    assert (E2E / "docker-compose.mock-llm.yml").is_file()
    assert (E2E / "docker-compose.ollama.yml").is_file()
    assert (E2E / "Dockerfile.scanner").is_file()
    assert (E2E / "Dockerfile.mock-ollama").is_file()
    assert (E2E / "mock_ollama_server.py").is_file()
    assert (E2E / "mock_decisions.jsonl").is_file()
    assert (E2E / "run_e2e.sh").is_file()
    assert (E2E / "run_e2e.ps1").is_file()
    assert (E2E / "run_e2e.cmd").is_file()
    assert (E2E / "run_e2e_real.sh").is_file()
    assert (E2E / "run_e2e_real.ps1").is_file()
    assert (E2E / "run_e2e_real.cmd").is_file()
    assert (E2E / "docker-compose.infra.yml").is_file()
    assert (E2E / "infra" / "nginx-lb.conf").is_file()
    assert (E2E / "infra" / "firewalled-entrypoint.sh").is_file()
    assert (E2E / "infra" / "VPN.md").is_file()
