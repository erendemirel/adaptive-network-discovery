from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Phase = Literal["host", "port", "service", "validation"]
HostStatus = Literal["unknown", "up", "down", "filtered"]
Latency = Literal["low", "medium", "high"]

VALID_ACTIONS: frozenset[str] = frozenset(
    {
        "nmap_ping",
        "nmap_ping_tcp",
        "nmap_ping_udp",
        "nmap_no_ping",
        "nmap_syn_scan",
        "nmap_connect_scan",
        "nmap_ack_scan",
        "nmap_window_scan",
        "nmap_udp_scan",
        "nmap_top_ports",
        "nmap_full_port_scan",
        "nmap_service_detection",
        "banner_grab",
        "tls_fingerprint",
        "http_probe",
        "https_probe",
        "retry_with_timing_slow",
        "retry_with_timing_normal",
        "retry_with_fragmentation",
        "retry_with_decoys",
        "repeat_last_action",
        "stop_scan",
    }
)


class Environment(BaseModel):
    external: bool = True
    stealth_required: bool = False
    latency: Latency = "medium"
    # Hints strategist + nmap tuning for wide scans (many hosts / subnets).
    large_network: bool = False
    # EDR/XDR-heavy sites: prefer connect scans, slow timing, no decoys/fragmentation.
    xdr_heavy: bool = False
    # Scanner and/or targets behind NAT / split-horizon DNS; visibility is partial.
    nated_environment: bool = False
    # Burst / rate limiting for nmap (often set together with xdr_heavy).
    low_noise: bool = False
    # Multi-vantage / federated merge: label this node's observations.
    scanner_id: str = ""
    # Indirect intel (inventory, CMDB, DHCP exports) — not executed, strategist context only.
    seed_hosts: list[str] = Field(default_factory=list)
    known_subnets: list[str] = Field(default_factory=list)
    # Operator or passive_local ARP harvest; list of {source, address?, note?}
    passive_hints: list[dict[str, Any]] = Field(default_factory=list)
    topology_notes: str = ""


class PerHostScan(BaseModel):
    """Per-IP (or per-target host) findings; required for correct multi-host merges."""

    address: str
    open_ports: list[int] = Field(default_factory=list)
    filtered_ports: list[int] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    # Nmap script id/output (truncated) from hostscript and port scripts
    scripts: list[dict[str, Any]] = Field(default_factory=list)
    # Parsed hints from common NSE outputs (http-title, ssl-cert, etc.)
    script_extracts: dict[str, Any] = Field(default_factory=dict)


class CurrentState(BaseModel):
    host_status: HostStatus = "unknown"
    discovered_ports: list[int] = Field(default_factory=list)
    filtered_ports: list[int] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)
    per_host: list[PerHostScan] = Field(default_factory=list)
    host_count: int = 0
    aggregate_notes: list[str] = Field(default_factory=list)
    # Seeds, ARP-local, DNS hints — weak signals; strategist should correlate with probes.
    indirect_endpoints: list[dict[str, Any]] = Field(default_factory=list)
    # Non-definitive reachability (rate-limit, filter, timeout) — do not equate with "down".
    reachability_hints: list[str] = Field(default_factory=list)
    # Token-efficient digest for the LLM (updated each merge in orchestrator).
    strategist_meta: dict[str, Any] = Field(default_factory=dict)
    # Rule-based hints (firewall/nat/visibility); refreshed each strategist step.
    scan_signals: dict[str, str] = Field(default_factory=dict)


class StrategistInput(BaseModel):
    target: str
    phase: Phase
    environment: Environment = Field(default_factory=Environment)
    current_state: CurrentState = Field(default_factory=CurrentState)
    last_action: str | None = None
    last_result: dict[str, Any] = Field(default_factory=dict)
    history: list[dict[str, Any]] = Field(default_factory=list)
    # Last few completed steps (action, target, outcome); filled in compact_strategist_input.
    recent_steps: list[dict[str, Any]] = Field(default_factory=list)


class RunTuningProposal(BaseModel):
    """Optional nmap knobs from the LLM; clamped to env bounds before execution."""

    timing: str | None = None
    version_intensity: int | None = Field(default=None, ge=0, le=9)
    max_scan_rate: str | None = None
    scan_delay: str | None = None
    host_timeout: str | None = None


class EnvironmentAdaptation(BaseModel):
    """Optional per-step Environment fields from the strategist (omit keys to leave unchanged)."""

    model_config = ConfigDict(extra="ignore")

    external: bool | None = None
    stealth_required: bool | None = None
    latency: Latency | None = None
    large_network: bool | None = None
    xdr_heavy: bool | None = None
    nated_environment: bool | None = None
    low_noise: bool | None = None


class StrategistDecision(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: str
    target: str
    phase: Phase
    reason: str
    confidence: float = Field(ge=0.0, le=1.0)
    run_tuning: RunTuningProposal | None = None
    environment_adaptation: EnvironmentAdaptation | None = None

    def validate_action(self) -> None:
        if self.action not in VALID_ACTIONS:
            allowed = ", ".join(sorted(VALID_ACTIONS))
            raise ValueError(
                f"Invalid action: {self.action!r}. Must be one of: {allowed}"
            )


class ScanHost(BaseModel):
    address: str
    status: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    host_scripts: list[dict[str, str]] = Field(default_factory=list)


class ScanPort(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str
    host_address: str = ""
    port_scripts: list[dict[str, str]] = Field(default_factory=list)
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None


class NmapRunSummary(BaseModel):
    command: list[str]
    exit_code: int
    stderr_tail: str = ""
    hosts: list[ScanHost] = Field(default_factory=list)
    ports: list[ScanPort] = Field(default_factory=list)
    raw_xml_path: str | None = None
    warnings: list[str] = Field(default_factory=list)
