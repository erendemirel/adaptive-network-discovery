from pathlib import Path

from network_scanner.models import Environment
from network_scanner.seeds import load_host_lines, reapply_seed_hosts_to_state


def test_load_host_lines_strips_comments(tmp_path: Path):
    p = tmp_path / "s.txt"
    p.write_text("10.0.0.1\n# c\n  10.0.0.2  \n", encoding="utf-8")
    assert load_host_lines(p) == ["10.0.0.1", "10.0.0.2"]


def test_reapply_replaces_seed_inventory_only(tmp_path: Path):
    env = Environment(seed_hosts=["old"])
    cur = {
        "indirect_endpoints": [
            {"source": "seed_inventory", "address": "old", "note": "x"},
            {"source": "passive_arp", "address": "10.9.9.9", "note": "n"},
        ]
    }
    env2 = reapply_seed_hosts_to_state(env, cur, ["10.1.1.1"])
    assert env2.seed_hosts == ["10.1.1.1"]
    addrs = [e["address"] for e in cur["indirect_endpoints"]]
    assert "10.1.1.1" in addrs
    assert "old" not in addrs
    assert "10.9.9.9" in addrs
