"""Unit tests for redaction helpers in sniffer.py."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sniffer import mask_ip, redact_text, check_iface_allowed, ALLOWED_IFACES


class TestMaskIP:
    def test_ipv4_masks_last_octet(self):
        assert mask_ip("192.168.1.42") == "192.168.1.xxx"

    def test_ipv4_masks_only_last_octet(self):
        result = mask_ip("10.0.0.1")
        assert result.startswith("10.0.0.")
        assert result.endswith("xxx")

    def test_none_passthrough(self):
        assert mask_ip(None) is None

    def test_ipv6_masks_last_segment(self):
        result = mask_ip("2001:db8::1")
        assert result.endswith("xxxx")

    def test_malformed_string_passthrough(self):
        assert mask_ip("not-an-ip") == "not-an-ip"


class TestRedactText:
    def test_redacts_email(self):
        text = "contact me at alice@example.com please"
        out = redact_text(text)
        assert "alice@example.com" not in out
        assert "[REDACTED_EMAIL]" in out

    def test_redacts_password_query_param(self):
        text = "GET /login?user=bob&password=hunter2 HTTP/1.1"
        out = redact_text(text)
        assert "hunter2" not in out
        assert "password=[REDACTED]" in out

    def test_redacts_token_query_param(self):
        text = "GET /api?token=abc123XYZ HTTP/1.1"
        out = redact_text(text)
        assert "abc123XYZ" not in out
        assert "token=[REDACTED]" in out

    def test_redacts_api_key_case_insensitive(self):
        text = "GET /x?API_KEY=zzz999 HTTP/1.1"
        out = redact_text(text)
        assert "zzz999" not in out

    def test_redacts_cookie_header(self):
        text = "Host: example.com\r\nCookie: sessionid=deadbeef12345\r\n"
        out = redact_text(text)
        assert "deadbeef12345" not in out
        assert "Cookie: [REDACTED]" in out

    def test_redacts_authorization_header(self):
        text = "Authorization: Bearer supersecrettoken\r\n"
        out = redact_text(text)
        assert "supersecrettoken" not in out
        assert "Authorization: [REDACTED]" in out

    def test_leaves_normal_text_untouched(self):
        text = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
        out = redact_text(text)
        assert out == text

    def test_empty_string(self):
        assert redact_text("") == ""

    def test_multiple_secrets_in_one_blob(self):
        text = "user@example.com token=abc password=def"
        out = redact_text(text)
        assert "user@example.com" not in out
        assert "abc" not in out
        assert "def" not in out


class TestIfaceAllowlist:
    def test_loopback_allowed(self):
        check_iface_allowed("lo")  # should not raise

    def test_arbitrary_iface_blocked(self):
        try:
            check_iface_allowed("eth0")
            assert False, "expected PermissionError"
        except PermissionError:
            pass

    def test_wifi_iface_blocked(self):
        try:
            check_iface_allowed("wlan0")
            assert False, "expected PermissionError"
        except PermissionError:
            pass

    def test_allowlist_is_small(self):
        # Guard against someone accidentally widening the allowlist to "*"
        assert len(ALLOWED_IFACES) < 10
        assert "eth0" not in ALLOWED_IFACES
        assert "wlan0" not in ALLOWED_IFACES
