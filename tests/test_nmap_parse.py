from network_scanner.nmap_runner import parse_nmap_xml, summary_to_result_dict


def test_parse_sample_xml():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.22"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="filtered"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    s = parse_nmap_xml(xml)
    assert s.exit_code == 0
    d = summary_to_result_dict(s)
    assert 80 in d["open_ports"]
    assert 443 in d["filtered_ports"]
    assert d["host_likely_up"] is True
    assert any(x["port"] == 80 for x in d["services"])
    assert len(d["per_host"]) >= 1
    assert d["per_host"][0]["address"] == "192.0.2.1"
    assert 80 in d["per_host"][0]["open_ports"]
