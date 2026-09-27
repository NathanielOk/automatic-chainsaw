"""Unit tests for packet decoding in sniffer.py, using a small pcap
built with scapy in-memory (no live capture, no network access needed)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from sniffer import parse_packet, read_pcap

SAMPLE_PCAP = os.path.join(os.path.dirname(__file__), "..", "sample_pcaps", "lab_traffic.pcap")


@pytest.fixture(scope="module")
def parsed_records():
    if not os.path.exists(SAMPLE_PCAP):
        pytest.skip("sample pcap not found; run the generator script first")
    records = []
    for pkt in read_pcap(SAMPLE_PCAP):
        rec = parse_packet(pkt)
        if rec is not None:
            records.append(rec)
    return records


def test_sample_pcap_has_records(parsed_records):
    assert len(parsed_records) >= 1


def test_dns_query_decoded(parsed_records):
    dns_recs = [r for r in parsed_records if r.proto == "DNS"]
    assert len(dns_recs) >= 1
    assert dns_recs[0].dns_query == "example.com"


def test_http_get_decoded(parsed_records):
    http_recs = [r for r in parsed_records if r.proto == "HTTP" and r.http_line and "GET" in r.http_line]
    assert len(http_recs) >= 1
    assert http_recs[0].http_host == "example.com"


def test_http_post_decoded(parsed_records):
    http_recs = [r for r in parsed_records if r.proto == "HTTP" and r.http_line and "POST" in r.http_line]
    assert len(http_recs) >= 1


def test_ip_addresses_present_before_redaction(parsed_records):
    # parse_packet should keep raw IPs; redaction happens later in redacted_dict()
    assert any(r.src_ip == "192.168.1.50" for r in parsed_records)


def test_redacted_dict_masks_ips(parsed_records):
    for rec in parsed_records:
        d = rec.redacted_dict()
        if d["src_ip"]:
            assert d["src_ip"].endswith(".xxx") or d["src_ip"].endswith("xxxx")


def test_redacted_dict_strips_secrets(parsed_records):
    for rec in parsed_records:
        d = rec.redacted_dict()
        blob = str(d)
        assert "abc123SECRET" not in blob
        assert "deadbeef12345" not in blob
        assert "supersecrettoken" not in blob
        assert "bob@example.com" not in blob
