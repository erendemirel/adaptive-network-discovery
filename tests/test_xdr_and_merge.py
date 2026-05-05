from network_scanner.models import CurrentState, Environment
from network_scanner.orchestrator import _xdr_resolve_scan_action
from network_scanner.state_import import merge_peer_final_state


def test_xdr_redirects_syn_and_ping():
    env = Environment(xdr_heavy=True)
    r, redir = _xdr_resolve_scan_action(env, "nmap_syn_scan")
    assert r == "nmap_connect_scan"
    assert redir
    r2, _ = _xdr_resolve_scan_action(env, "nmap_ping")
    assert r2 == "nmap_no_ping"


def test_merge_peer_tags_per_host():
    base = CurrentState().model_dump()
    peer = {
        "discovered_ports": [443],
        "filtered_ports": [],
        "services": [],
        "per_host": [
            {
                "address": "10.0.0.1",
                "open_ports": [443],
                "filtered_ports": [],
                "services": [],
                "notes": [],
                "scripts": [],
            }
        ],
        "host_count": 1,
    }
    m = merge_peer_final_state(base, peer, "edge-a")
    notes = m["per_host"][0].get("notes") if m["per_host"] else []
    assert any("peer:edge-a" in str(n) for n in notes)
