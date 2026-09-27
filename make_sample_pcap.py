"""
Regenerates sample_pcaps/lab_traffic.pcap: a small, synthetic capture built
entirely in-memory with scapy (no live capture, no network access). This
is the "victim service" traffic instructors can hand out, or students can
regenerate themselves to test the sniffer's decoding and redaction.

Run:
    python tests/make_sample_pcap.py
"""
import os

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "sample_pcaps", "lab_traffic.pcap")


def build_packets():
    pkts = []

    # A DNS query, as if the victim service resolved example.com
    pkts.append(
        Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    # An HTTP GET with a secret-looking token in the query string, a
    # session cookie, and an Authorization header -- all things the
    # sniffer's redaction layer must strip before logging.
    http_get = (
        "GET /login?user=alice&token=abc123SECRET HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Cookie: sessionid=deadbeef12345\r\n"
        "Authorization: Bearer supersecrettoken\r\n"
        "User-Agent: lab-test\r\n\r\n"
    )
    pkts.append(
        Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=51000, dport=80)
        / Raw(load=http_get.encode())
    )

    # An HTTP POST with an email address in the body.
    http_post = "POST /contact HTTP/1.1\r\nHost: example.com\r\n\r\nemail=bob@example.com&msg=hello"
    pkts.append(
        Ether() / IP(src="192.168.1.51", dst="93.184.216.34") / TCP(sport=51001, dport=80)
        / Raw(load=http_post.encode())
    )

    return pkts


if __name__ == "__main__":
    packets = build_packets()
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    wrpcap(OUT_PATH, packets)
    print(f"Wrote {len(packets)} synthetic packets to {OUT_PATH}")
