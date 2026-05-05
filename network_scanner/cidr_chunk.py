from __future__ import annotations

import ipaddress


def ipv4_subnets(target: str, new_prefix: int) -> list[str]:
    """
    Split an IPv4 CIDR into smaller subnets (e.g. 10.0.0.0/16 + new_prefix=24 → /24s).
    Non-IPv4 or non-CIDR targets are returned as a single-element list unchanged.
    """
    t = (target or "").strip()
    if "/" not in t:
        return [t]
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        return [t]
    if not isinstance(net, ipaddress.IPv4Network):
        return [t]
    if new_prefix < int(net.prefixlen):
        raise ValueError(
            f"chunk prefix /{new_prefix} must be >= target /{net.prefixlen} (would expand, not split)"
        )
    if new_prefix > 32:
        raise ValueError("invalid IPv4 prefix")
    return [str(s) for s in net.subnets(new_prefix=new_prefix)]


def should_chunk_target(target: str, chunk_prefix: int | None) -> bool:
    if chunk_prefix is None:
        return False
    return "/" in (target or "") and chunk_prefix >= 0
