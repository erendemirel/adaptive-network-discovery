from network_scanner.nmap_runner import merge_state_from_result, parse_nmap_xml, summary_to_result_dict


def test_multi_host_per_host_attribution():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.0.2.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    </ports>
  </host>
</nmaprun>
"""
    s = parse_nmap_xml(xml)
    d = summary_to_result_dict(s)
    assert d["host_count"] >= 2
    addrs = {row["address"]: row for row in d["per_host"]}
    assert "192.0.2.1" in addrs and "192.0.2.2" in addrs
    assert 22 in addrs["192.0.2.1"]["open_ports"]
    assert 80 in addrs["192.0.2.2"]["open_ports"]
    assert {22, 80} == set(d["open_ports"])


def test_merge_keeps_per_host_separate():
    prev = {
        "host_status": "unknown",
        "discovered_ports": [22],
        "filtered_ports": [],
        "services": [{"port": 22, "protocol": "tcp", "host": "192.0.2.1", "service_name": "ssh"}],
        "anomalies": [],
        "per_host": [
            {
                "address": "192.0.2.1",
                "open_ports": [22],
                "filtered_ports": [],
                "services": [{"port": 22, "protocol": "tcp", "service_name": "ssh"}],
                "notes": [],
                "scripts": [],
            }
        ],
        "host_count": 1,
        "aggregate_notes": [],
        "indirect_endpoints": [],
        "reachability_hints": [],
        "strategist_meta": {},
    }
    result = {
        "open_ports": [80],
        "filtered_ports": [],
        "services": [{"port": 80, "protocol": "tcp", "host": "192.0.2.2", "service_name": "http"}],
        "per_host": [
            {
                "address": "192.0.2.2",
                "open_ports": [80],
                "filtered_ports": [],
                "services": [{"port": 80, "protocol": "tcp", "service_name": "http"}],
                "scripts": [],
            }
        ],
        "host_count": 1,
        "host_likely_up": True,
        "anomalies": [],
    }
    m = merge_state_from_result(prev, result)
    by = {h["address"]: h for h in m["per_host"]}
    assert 22 in by["192.0.2.1"]["open_ports"]
    assert 80 in by["192.0.2.2"]["open_ports"]
    assert set(m["discovered_ports"]) == {22, 80}


def test_merge_script_extracts_per_host():
    prev = {
        "host_status": "unknown",
        "discovered_ports": [],
        "filtered_ports": [],
        "services": [],
        "anomalies": [],
        "per_host": [
            {
                "address": "192.0.2.1",
                "open_ports": [80],
                "filtered_ports": [],
                "services": [],
                "notes": [],
                "scripts": [],
                "script_extracts": {"http_titles": ["A"]},
            }
        ],
        "host_count": 1,
        "aggregate_notes": [],
        "indirect_endpoints": [],
        "reachability_hints": [],
        "strategist_meta": {},
    }
    result = {
        "open_ports": [80],
        "filtered_ports": [],
        "services": [],
        "per_host": [
            {
                "address": "192.0.2.1",
                "open_ports": [80],
                "filtered_ports": [],
                "services": [],
                "scripts": [],
                "script_extracts": {"http_titles": ["B"], "tls_subjects": ["CN=x"]},
            }
        ],
        "host_count": 1,
        "host_likely_up": True,
        "anomalies": [],
    }
    m = merge_state_from_result(prev, result)
    ex = {h["address"]: h.get("script_extracts") for h in m["per_host"]}["192.0.2.1"]
    assert ex["http_titles"] == ["A", "B"]
    assert ex["tls_subjects"] == ["CN=x"]
