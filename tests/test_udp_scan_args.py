from network_scanner.nmap_runner import RunContext, build_nmap_command


def test_udp_top_ports_default():
    ctx = RunContext(low_noise=False)
    cmd = build_nmap_command("nmap_udp_scan", "127.0.0.1", ctx)
    i = cmd.index("--top-ports")
    assert cmd[i + 1] == "100"


def test_udp_top_ports_low_noise():
    ctx = RunContext(low_noise=True)
    cmd = build_nmap_command("nmap_udp_scan", "127.0.0.1", ctx)
    i = cmd.index("--top-ports")
    assert cmd[i + 1] == "20"


def test_udp_top_ports_ctx_override():
    ctx = RunContext(low_noise=True, udp_top_ports="9")
    cmd = build_nmap_command("nmap_udp_scan", "127.0.0.1", ctx)
    i = cmd.index("--top-ports")
    assert cmd[i + 1] == "9"


def test_udp_top_ports_env_override(monkeypatch):
    monkeypatch.setenv("ADAPTIVE_SCAN_UDP_TOP_PORTS", "7")
    ctx = RunContext(low_noise=False)
    cmd = build_nmap_command("nmap_udp_scan", "127.0.0.1", ctx)
    i = cmd.index("--top-ports")
    assert cmd[i + 1] == "7"
    monkeypatch.delenv("ADAPTIVE_SCAN_UDP_TOP_PORTS", raising=False)
