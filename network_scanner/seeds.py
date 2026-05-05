from __future__ import annotations

from pathlib import Path

from network_scanner.models import Environment


def load_host_lines(path: Path) -> list[str]:
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def reapply_seed_hosts_to_state(
    env: Environment,
    current_dict: dict,
    lines: list[str],
) -> Environment:
    """Replace env.seed_hosts and seed_inventory indirect rows; keep other indirect sources."""
    new_env = env.model_copy(update={"seed_hosts": lines})
    remaining = [
        e
        for e in (current_dict.get("indirect_endpoints") or [])
        if not (isinstance(e, dict) and e.get("source") == "seed_inventory")
    ]
    for s in lines:
        t = (s or "").strip()
        if t:
            remaining.append(
                {
                    "source": "seed_inventory",
                    "address": t,
                    "note": "Operator inventory / CMDB / DHCP export (correlate with probes)",
                }
            )
    current_dict["indirect_endpoints"] = remaining
    return new_env
