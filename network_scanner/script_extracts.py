from __future__ import annotations

import re
from typing import Any


def _dedupe_strs(xs: list[str], cap: int = 24) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in xs:
        t = (x or "").strip()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t[:500])
        if len(out) >= cap:
            break
    return out


def extract_from_script_entries(scripts: list[dict[str, Any]]) -> dict[str, Any]:
    """Pull compact fields from common NSE outputs for strategist / JSON consumers."""
    titles: list[str] = []
    servers: list[str] = []
    tls_subjects: list[str] = []
    tls_notes: list[str] = []

    for s in scripts:
        sid = (s.get("id") or "").lower()
        output = s.get("output") or ""
        if not output:
            continue

        if sid == "http-title":
            m = re.search(r"(?i)(?:\|[^|\n]*?)?http-title:\s*(.+?)(?:\n|$)", output)
            if not m:
                m = re.search(r"(?i)\btitle:\s*(.+?)(?:\n|$)", output)
            if m:
                titles.append(m.group(1).strip())
            else:
                line = output.strip().split("\n", 1)[0].strip()
                if line:
                    titles.append(line[:300])

        if sid in ("http-server-header", "http-headers"):
            for m in re.finditer(
                r"(?i)(?:Server|http-server-header):\s*([^\n\r]+)", output
            ):
                servers.append(m.group(1).strip())

        if sid in ("ssl-cert", "ssl-enum-ciphers"):
            for m in re.finditer(r"(?i)Subject:\s*([^\n\r]+)", output):
                tls_subjects.append(m.group(1).strip())
            for m in re.finditer(r"(?i)Issuer:\s*([^\n\r]+)", output):
                tls_notes.append("issuer:" + m.group(1).strip()[:120])
            if re.search(r"(?i)\b(weak|NULL|EXPORT|anon|RC4|DES\b)", output):
                tls_notes.append("possible_weak_cipher_mentions")

    out: dict[str, Any] = {}
    t2 = _dedupe_strs(titles, 16)
    s2 = _dedupe_strs(servers, 16)
    ts = _dedupe_strs(tls_subjects, 8)
    tn = _dedupe_strs(tls_notes, 12)
    if t2:
        out["http_titles"] = t2
    if s2:
        out["http_servers"] = s2
    if ts:
        out["tls_subjects"] = ts
    if tn:
        out["tls_notes"] = tn
    return out


def merge_script_extracts(
    a: dict[str, Any] | None,
    b: dict[str, Any] | None,
) -> dict[str, Any]:
    if not a and not b:
        return {}
    keys = set((a or {}).keys()) | set((b or {}).keys())
    merged: dict[str, Any] = {}
    for k in keys:
        la = list((a or {}).get(k) or [])
        lb = list((b or {}).get(k) or [])
        if not isinstance(la, list):
            la = [la]
        if not isinstance(lb, list):
            lb = [lb]
        if la or lb:
            merged[k] = _dedupe_strs(
                [str(x) for x in la + lb if x is not None],
                24,
            )
    return merged
