from __future__ import annotations

import ipaddress

from network_scanner.models import Environment, EnvironmentAdaptation, Latency


def infer_initial_environment(target: str) -> Environment:
    """
    Default scan posture without CLI flags: neutral start, wide targets marked large_network.
    The LLM can adapt Environment each step via environment_adaptation.
    """
    t = (target or "").strip()
    large_network = False
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses > 64 or net.prefixlen <= 26:
                large_network = True
        except ValueError:
            pass

    return Environment(
        external=True,
        stealth_required=False,
        latency="medium",
        large_network=large_network,
        xdr_heavy=False,
        nated_environment=False,
        low_noise=False,
        scanner_id="",
        seed_hosts=[],
        known_subnets=[],
        passive_hints=[],
        topology_notes="",
    )


def _coerce_environment(env: Environment) -> Environment:
    """xdr_heavy implies low-noise-style nmap path (matches prior CLI behavior)."""
    if env.xdr_heavy and not env.low_noise:
        return env.model_copy(update={"low_noise": True})
    return env


def apply_environment_adaptation(
    env: Environment,
    adaptation: EnvironmentAdaptation | None,
) -> Environment:
    if adaptation is None:
        return _coerce_environment(env)
    data = env.model_dump()
    for name in (
        "external",
        "stealth_required",
        "latency",
        "large_network",
        "xdr_heavy",
        "nated_environment",
        "low_noise",
    ):
        v = getattr(adaptation, name, None)
        if v is not None:
            if name == "latency" and v not in ("low", "medium", "high"):
                continue
            data[name] = v
    return _coerce_environment(Environment.model_validate(data))
