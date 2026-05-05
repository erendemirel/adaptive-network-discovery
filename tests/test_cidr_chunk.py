from network_scanner.cidr_chunk import ipv4_subnets, should_chunk_target


def test_ipv4_subnets_splits():
    out = ipv4_subnets("10.0.0.0/24", 26)
    assert len(out) == 4
    assert "10.0.0.0/26" in out
    assert "10.0.0.192/26" in out


def test_ipv4_subnets_non_cidr_unchanged():
    assert ipv4_subnets("10.0.0.1", 24) == ["10.0.0.1"]


def test_should_chunk_target():
    assert should_chunk_target("10.0.0.0/8", 16) is True
    assert should_chunk_target("10.0.0.1", 16) is False
    assert should_chunk_target("10.0.0.0/8", None) is False
