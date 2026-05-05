from network_scanner.auto_env import apply_environment_adaptation, infer_initial_environment
from network_scanner.models import Environment, EnvironmentAdaptation


def test_infer_large_network_from_wide_cidr():
    env = infer_initial_environment("10.0.0.0/8")
    assert env.large_network is True


def test_infer_not_large_for_single_host():
    env = infer_initial_environment("192.0.2.1")
    assert env.large_network is False


def test_infer_large_when_many_addresses_or_slash_26_or_wider():
    assert infer_initial_environment("10.0.0.0/24").large_network is True  # 256 > 64
    env_small = infer_initial_environment("10.0.0.0/28")
    assert env_small.large_network is False
    assert infer_initial_environment("10.0.0.0/26").large_network is True  # prefixlen <= 26


def test_apply_adaptation_merges_partial():
    base = Environment(latency="medium", low_noise=False)
    out = apply_environment_adaptation(
        base, EnvironmentAdaptation(low_noise=True, latency="high")
    )
    assert out.low_noise is True
    assert out.latency == "high"


def test_xdr_heavy_coerces_low_noise():
    base = Environment(xdr_heavy=True, low_noise=False)
    out = apply_environment_adaptation(base, None)
    assert out.low_noise is True
