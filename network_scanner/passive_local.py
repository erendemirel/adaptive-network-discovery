from __future__ import annotations

import logging
import re
import subprocess
import sys
from typing import Any

logger = logging.getLogger(__name__)

# IPv4 pattern (rough, good enough for ARP/neigh output)
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


def _run_capture(cmd: list[str], timeout: float = 15.0) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.debug("passive probe failed: %s", e)
        return ""


def collect_arp_neighbors(max_entries: int = 512) -> list[dict[str, Any]]:
    """
    Best-effort L2 neighbor list from the scanning host only (local segment).
    Does not replace active discovery; feeds indirect_endpoints for NAT/XDR context.
    """
    text = ""
    if sys.platform == "win32":
        text = _run_capture(["arp", "-a"])
    else:
        text = _run_capture(["ip", "-4", "neigh", "show"])
        if not text.strip():
            text = _run_capture(["arp", "-a"])

    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for m in _IPV4.finditer(text):
        ip = m.group(0)
        if ip in ("0.0.0.0", "255.255.255.255"):
            continue
        if ip not in seen:
            seen.add(ip)
            out.append(
                {
                    "source": "arp_local",
                    "address": ip,
                    "note": "Seen on scanner host ARP/neighbor table (L2-local only)",
                }
            )
        if len(out) >= max_entries:
            break
    return out
