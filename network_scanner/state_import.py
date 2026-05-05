from __future__ import annotations

from typing import Any


def merge_peer_final_state(
    base: dict[str, Any],
    peer_state: dict[str, Any],
    peer_scanner_id: str,
) -> dict[str, Any]:
    """
    Merge another scanner node's final_state (or compatible dict) into base CurrentState-shaped dict.
    Tags per_host rows with peer:{id} for provenance.
    """
    if not peer_state:
        return base

    result: dict[str, Any] = {
        "open_ports": list(peer_state.get("discovered_ports") or []),
        "filtered_ports": list(peer_state.get("filtered_ports") or []),
        "services": list(peer_state.get("services") or []),
        "per_host": [],
        "host_count": int(peer_state.get("host_count") or 0),
        "host_likely_up": bool(
            peer_state.get("discovered_ports") or peer_state.get("per_host")
        ),
        "anomalies": [],
    }
    tag = f"peer:{peer_scanner_id}"
    for row in peer_state.get("per_host") or []:
        if not isinstance(row, dict):
            continue
        nr = dict(row)
        notes = list(nr.get("notes") or [])
        if tag not in notes:
            notes.append(tag)
        nr["notes"] = notes
        result["per_host"].append(nr)

    from network_scanner.nmap_runner import merge_state_from_result

    merged = merge_state_from_result(base, result)

    for ep in peer_state.get("indirect_endpoints") or []:
        if isinstance(ep, dict):
            lst = list(merged.get("indirect_endpoints") or [])
            e2 = dict(ep)
            e2.setdefault("via_scanner", peer_scanner_id)
            lst.append(e2)
            merged["indirect_endpoints"] = lst

    an = list(merged.get("aggregate_notes") or [])
    note = f"Merged scan state from scanner {peer_scanner_id!r}"
    if note not in an:
        an.append(note)
    merged["aggregate_notes"] = an
    return merged
