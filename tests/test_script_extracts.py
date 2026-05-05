from network_scanner.script_extracts import (
    extract_from_script_entries,
    merge_script_extracts,
)


def test_extract_http_title():
    scripts = [{"id": "http-title", "output": "80/tcp open http\n|_http-title: My Site\n"}]
    ex = extract_from_script_entries(scripts)
    assert "http_titles" in ex
    assert any("My Site" in t for t in ex["http_titles"])


def test_extract_ssl_subject():
    scripts = [
        {
            "id": "ssl-cert",
            "output": "Subject: commonName=example.org\nIssuer: CN=Test CA\n",
        }
    ]
    ex = extract_from_script_entries(scripts)
    assert "tls_subjects" in ex
    assert any("example.org" in s for s in ex["tls_subjects"])


def test_merge_script_extracts_dedupes():
    a = {"http_titles": ["A"], "http_servers": ["nginx"]}
    b = {"http_titles": ["A", "B"], "tls_subjects": ["CN=x"]}
    m = merge_script_extracts(a, b)
    assert m["http_titles"] == ["A", "B"]
    assert m["http_servers"] == ["nginx"]
    assert m["tls_subjects"] == ["CN=x"]
