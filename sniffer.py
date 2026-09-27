#!/usr/bin/env python3
"""
sniffer.py — Copilot-Assisted Packet Sniffer (lab edition)

ETHICAL / SCOPE NOTE:
    This tool is built for a classroom lab. It must only ever be pointed at:
      - loopback ("lo" / "Loopback"), or
      - an instructor-provided lab interface listed in ALLOWED_IFACES, or
      - a .pcap file you already have permission to read (default mode).

    It will refuse to sniff live on any interface not in the allowlist, and
    it redacts sensitive fields (IPs, emails, tokens, cookies, auth headers)
    before anything is written to a log or printed to stdout.

Usage:
    # Safe default: read from a pcap file
    python sniffer.py --pcap sample_pcaps/lab_traffic.pcap

    # Live capture (only if permissions + allowlist allow it)
    python sniffer.py --iface lo --count 25 --filter "tcp port 80 or udp port 53"

    # Write redacted JSON-lines log
    python sniffer.py --pcap sample_pcaps/lab_traffic.pcap --out capture.log.jsonl
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

# --- Allowlist: the only interfaces this tool will EVER sniff live on. ---
# Instructors: add the lab VM interface name here (e.g. "eth0") if needed.
ALLOWED_IFACES = {"lo", "Loopback", "Loopback Pseudo-Interface 1", "lo0"}

# ----------------------------------------------------------------------------
# Redaction
# ----------------------------------------------------------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SECRET_QS_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|access_token|api_key|apikey|secret|session|sessid|auth)=([^&\s]+)"
)
COOKIE_HEADER_RE = re.compile(r"(?im)^(Cookie|Set-Cookie):.*$")
AUTH_HEADER_RE = re.compile(r"(?im)^(Authorization):.*$")


def mask_ip(ip: Optional[str]) -> Optional[str]:
    """Mask the last octet of an IPv4 address: 192.168.1.42 -> 192.168.1.xxx"""
    if not ip:
        return ip
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["xxx"])
    # IPv6 or unrecognized format: mask the trailing segment
    if ":" in ip:
        segs = ip.split(":")
        segs[-1] = "xxxx"
        return ":".join(segs)
    return ip


def redact_text(text: str) -> str:
    """Redact emails, secret-looking query params, cookies, and auth headers
    from a blob of text (e.g. an HTTP request)."""
    if not text:
        return text
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = SECRET_QS_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = COOKIE_HEADER_RE.sub(lambda m: f"{m.group(1)}: [REDACTED]", text)
    text = AUTH_HEADER_RE.sub(lambda m: f"{m.group(1)}: [REDACTED]", text)
    return text


# ----------------------------------------------------------------------------
# Parsed packet record
# ----------------------------------------------------------------------------

@dataclass
class PacketRecord:
    ts: float
    proto: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    dns_query: Optional[str] = None
    http_line: Optional[str] = None
    http_host: Optional[str] = None
    summary: str = ""

    def redacted_dict(self) -> dict:
        masked_src = mask_ip(self.src_ip)
        masked_dst = mask_ip(self.dst_ip)
        d = {
            "ts": self.ts,
            "proto": self.proto,
            "src_ip": masked_src,
            "dst_ip": masked_dst,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "dns_query": self.dns_query,
            "http_host": redact_text(self.http_host) if self.http_host else None,
            "http_line": redact_text(self.http_line) if self.http_line else None,
            "summary": f"{self.proto} {masked_src}:{self.src_port or ''} -> {masked_dst}:{self.dst_port or ''}",
        }
        return d


# ----------------------------------------------------------------------------
# Decoding (scapy-based)
# ----------------------------------------------------------------------------

def parse_packet(pkt) -> Optional[PacketRecord]:
    """Turn a scapy packet into a PacketRecord. Returns None if nothing
    interesting (non-IP) was found."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.packet import Raw

    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    ts = float(getattr(pkt, "time", time.time()))
    rec = PacketRecord(ts=ts, proto="IP", src_ip=ip.src, dst_ip=ip.dst)

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        rec.proto = "TCP"
        rec.src_port = int(tcp.sport)
        rec.dst_port = int(tcp.dport)

        if pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw].load).decode("utf-8", errors="replace")
            except Exception:
                payload = ""
            if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                rec.proto = "HTTP"
                first_line = payload.splitlines()[0] if payload.splitlines() else ""
                rec.http_line = first_line
                host_match = re.search(r"(?im)^Host:\s*(.+)$", payload)
                if host_match:
                    rec.http_host = host_match.group(1).strip()

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        rec.proto = "UDP"
        rec.src_port = int(udp.sport)
        rec.dst_port = int(udp.dport)

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            rec.proto = "DNS"
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            except Exception:
                qname = str(pkt[DNSQR].qname)
            rec.dns_query = qname

    rec.summary = f"{rec.proto} {rec.src_ip}:{rec.src_port or ''} -> {rec.dst_ip}:{rec.dst_port or ''}"
    return rec


# ----------------------------------------------------------------------------
# Capture sources
# ----------------------------------------------------------------------------

def read_pcap(path: str):
    # Import these BEFORE rdpcap so scapy's bind_layers() calls (e.g.
    # Ethernet ethertype 0x0800 -> IP) are registered before packets are
    # dissected off disk. Importing only scapy.layers.l2 leaves Ether's
    # payload undissected as raw bytes.
    import scapy.layers.l2      # noqa: F401
    import scapy.layers.inet    # noqa: F401
    import scapy.layers.dns     # noqa: F401
    from scapy.utils import rdpcap
    for pkt in rdpcap(path):
        yield pkt


def check_iface_allowed(iface: str) -> None:
    """Raise PermissionError if iface is not on the allowlist. Called eagerly
    (not inside a generator) so the check always runs before any capture
    attempt, regardless of whether the caller ever iterates the result."""
    if iface not in ALLOWED_IFACES:
        raise PermissionError(
            f"Refusing to sniff on '{iface}': not in ALLOWED_IFACES {sorted(ALLOWED_IFACES)}. "
            "This tool only captures on loopback or an instructor-approved lab interface. "
            "Use --pcap to analyze a capture file instead."
        )


def sniff_live(iface: str, count: int, bpf_filter: Optional[str]):
    check_iface_allowed(iface)  # runs immediately, not deferred to first iteration
    from scapy.sendrecv import sniff
    packets = sniff(iface=iface, count=count, filter=bpf_filter, timeout=60)
    for pkt in packets:
        yield pkt


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Ethical lab packet sniffer (pcap-first).")
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument("--pcap", help="Path to a .pcap/.pcapng file to analyze (default/safe mode).")
    src.add_argument("--iface", help="Live interface to sniff (must be allowlisted, e.g. 'lo').")
    p.add_argument("--count", type=int, default=25, help="Number of packets to capture live (default 25).")
    p.add_argument("--filter", dest="bpf_filter", default=None,
                    help='BPF filter, e.g. "tcp port 80 or udp port 53".')
    p.add_argument("--out", default=None, help="Write redacted JSON-lines output to this file.")
    return p


def main(argv=None):
    args = build_arg_parser().parse_args(argv)

    if not args.pcap and not args.iface:
        print("No --pcap or --iface given; defaulting to pcap mode is required. "
              "Pass --pcap <file> or an allowlisted --iface. Exiting.", file=sys.stderr)
        return 2

    if args.iface:
        try:
            check_iface_allowed(args.iface)  # eager check, before the generator is ever touched
            packet_source = sniff_live(args.iface, args.count, args.bpf_filter)
        except PermissionError as e:
            print(f"[BLOCKED] {e}", file=sys.stderr)
            return 1
        except Exception as e:
            # Common case: no capture privileges (need root / CAP_NET_RAW).
            print(f"[WARN] Live capture failed ({e}). "
                  f"Falling back is recommended: rerun with --pcap.", file=sys.stderr)
            return 1
    else:
        if not os.path.exists(args.pcap):
            print(f"[ERROR] pcap file not found: {args.pcap}", file=sys.stderr)
            return 1
        packet_source = read_pcap(args.pcap)

    out_fh = open(args.out, "w") if args.out else None
    count = 0
    try:
        for pkt in packet_source:
            rec = parse_packet(pkt)
            if rec is None:
                continue
            d = rec.redacted_dict()
            line = json.dumps(d)
            print(line)
            if out_fh:
                out_fh.write(line + "\n")
            count += 1
    finally:
        if out_fh:
            out_fh.close()

    print(f"\n[done] {count} packets parsed and redacted.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
