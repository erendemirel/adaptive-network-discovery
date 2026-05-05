import tempfile

from network_scanner.nmap_runner import parse_nmap_xml_file, parse_nmap_xml, summary_to_result_dict


def test_port_and_host_scripts_in_summary():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostscript>
      <script id="test-host" output="hello"/>
    </hostscript>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
        <script id="http-title" output="Welcome"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    s = parse_nmap_xml(xml)
    d = summary_to_result_dict(s)
    row = d["per_host"][0]
    assert any(x.get("id") == "http-title" for x in row["scripts"])
    assert any(x.get("scope") == "host" and x.get("id") == "test-host" for x in row["scripts"])
    assert row.get("script_extracts", {}).get("http_titles")


def test_iterparse_file_matches_string_parse():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, encoding="utf-8") as f:
        f.write(xml)
        path = f.name
    try:
        a = summary_to_result_dict(parse_nmap_xml(xml))
        b = summary_to_result_dict(parse_nmap_xml_file(path))
    finally:
        import os

        os.unlink(path)
    assert a["open_ports"] == b["open_ports"]
    assert a["per_host"][0]["address"] == b["per_host"][0]["address"]
