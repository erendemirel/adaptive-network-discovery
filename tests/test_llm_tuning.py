from network_scanner.llm_tuning import apply_llm_tuning_to_context
from network_scanner.models import Environment, RunTuningProposal, StrategistDecision
from network_scanner.nmap_runner import RunContext


def test_strategist_decision_accepts_run_tuning():
    d = StrategistDecision.model_validate(
        {
            "action": "nmap_ping",
            "target": "x",
            "phase": "host",
            "reason": "t",
            "confidence": 0.5,
            "run_tuning": {"timing": "T3", "version_intensity": 5},
        }
    )
    assert d.run_tuning is not None
    assert d.run_tuning.timing == "T3"
    assert d.run_tuning.version_intensity == 5


def test_strategist_decision_ignores_unknown_keys():
    d = StrategistDecision.model_validate(
        {
            "action": "stop_scan",
            "target": "x",
            "phase": "host",
            "reason": "done",
            "confidence": 0.9,
            "extra_llm_field": 123,
        }
    )
    assert not hasattr(d, "extra_llm_field")


def test_apply_tuning_disabled_when_env_off(monkeypatch):
    monkeypatch.setenv("ADAPTIVE_SCAN_LLM_TUNING", "0")
    ctx = RunContext(low_noise=False)
    prop = RunTuningProposal(timing="T4")
    ctx2, applied = apply_llm_tuning_to_context(ctx, prop, env=Environment())
    assert applied == {}
    assert ctx2.llm_timing is None


def test_apply_tuning_clamps_timing_low_noise():
    ctx = RunContext(low_noise=True)
    prop = RunTuningProposal(timing="T5")
    ctx2, applied = apply_llm_tuning_to_context(ctx, prop, env=Environment(low_noise=True))
    assert applied == {}


def test_apply_tuning_accepts_allowed_timing():
    ctx = RunContext(low_noise=False)
    prop = RunTuningProposal(timing="T4")
    ctx2, applied = apply_llm_tuning_to_context(ctx, prop, env=Environment())
    assert applied.get("timing") == "T4"
    assert ctx2.llm_timing == "T4"


def test_max_scan_rate_requires_existing_caps(monkeypatch):
    monkeypatch.delenv("ADAPTIVE_SCAN_GLOBAL_MAX_SCAN_RATE", raising=False)
    monkeypatch.delenv("ADAPTIVE_SCAN_XDR_MAX_SCAN_RATE", raising=False)
    monkeypatch.delenv("ADAPTIVE_SCAN_MAX_SCAN_RATE", raising=False)
    ctx = RunContext(low_noise=False, large_network=False)
    prop = RunTuningProposal(max_scan_rate="500")
    ctx2, applied = apply_llm_tuning_to_context(ctx, prop, env=Environment())
    assert "max_scan_rate" not in applied
    assert ctx2.llm_max_scan_rate is None


def test_max_scan_rate_clamped_to_global(monkeypatch):
    monkeypatch.setenv("ADAPTIVE_SCAN_GLOBAL_MAX_SCAN_RATE", "80")
    ctx = RunContext(low_noise=False, large_network=False)
    prop = RunTuningProposal(max_scan_rate="500")
    ctx2, applied = apply_llm_tuning_to_context(ctx, prop, env=Environment())
    assert applied["max_scan_rate"] == 80
    assert ctx2.llm_max_scan_rate == "80"


def test_version_intensity_respects_env_cap(monkeypatch):
    monkeypatch.setenv("ADAPTIVE_SCAN_VERSION_INTENSITY", "4")
    ctx = RunContext(low_noise=False)
    prop = RunTuningProposal(version_intensity=9)
    ctx2, applied = apply_llm_tuning_to_context(ctx, prop, env=Environment())
    assert applied["version_intensity"] == 4
    assert ctx2.llm_version_intensity == "4"


def test_build_nmap_base_uses_llm_timing():
    ctx = RunContext(
        low_noise=False,
        stealth=False,
        latency="medium",
        llm_timing="T4",
    )
    from network_scanner.nmap_runner import _build_nmap_base

    parts = _build_nmap_base(ctx)
    assert "-T4" in parts
