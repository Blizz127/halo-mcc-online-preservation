"""Pure-Python pcap reader for passive connection-topology evidence.

Written from scratch because this host has neither `tshark` nor `scapy`: only
`tcpdump` (which writes the file) and the standard library are available. Reads
only what P0-C1 is authorized to establish — packet timestamps, L3/L4 addressing,
DNS query names, and TLS ClientHello SNI. It deliberately does **not** reassemble
TCP streams or decode application payloads beyond the TLS handshake, so no HTTP
body, header, cookie, or credential can be extracted by this module even if one
were present in the file.

Captures for this rung are taken with a small `--snapshot-length`, so most packets
are truncated on disk before this parser ever sees them: request/response bodies
physically are not in the file. A ClientHello that is truncated past the SNI
extension simply yields `None` rather than a partial guess.

Link types handled: LINKTYPE_ETHERNET (1), LINKTYPE_LINUX_SLL (113), and
LINKTYPE_LINUX_SLL2 (276). `tcpdump -i any` on libpcap >= 1.10 writes SLL2, which
is why both cooked variants matter here.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_ETHERTYPE_VLAN = 0x8100

_PROTO_TCP = 6
_PROTO_UDP = 17

# pcap magic numbers: (magic, endian_prefix, timestamps_are_nanoseconds)
_MAGICS = {
    0xA1B2C3D4: ("<", False),
    0xD4C3B2A1: (">", False),
    0xA1B23C4D: ("<", True),
    0x4D3CB2A1: (">", True),
}


class PcapFormatError(ValueError):
    pass


@dataclass
class Packet:
    timestamp: float
    protocol: str  # "tcp" | "udp"
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes = field(repr=False, default=b"")
    truncated: bool = False


def _parse_global_header(data: bytes) -> tuple[str, bool, int, int]:
    if len(data) < 24:
        raise PcapFormatError("file shorter than a pcap global header")
    (magic,) = struct.unpack("<I", data[:4])
    if magic not in _MAGICS:
        (magic_be,) = struct.unpack(">I", data[:4])
        if magic_be not in _MAGICS:
            raise PcapFormatError(f"not a pcap file (magic {magic:#x})")
        magic = magic_be
    endian, nanoseconds = _MAGICS[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    return endian, nanoseconds, linktype, 24


def _strip_link_layer(frame: bytes, linktype: int) -> tuple[int, bytes] | None:
    """Return (ethertype, l3_bytes) or None when the frame is not IP."""
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack(">H", frame[12:14])[0]
        offset = 14
        # Tolerate a single 802.1Q VLAN tag.
        if ethertype == _ETHERTYPE_VLAN:
            if len(frame) < 18:
                return None
            ethertype = struct.unpack(">H", frame[16:18])[0]
            offset = 18
        return ethertype, frame[offset:]

    if linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        return struct.unpack(">H", frame[14:16])[0], frame[16:]

    if linktype == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return None
        return struct.unpack(">H", frame[0:2])[0], frame[20:]

    return None


def _parse_ip(ethertype: int, data: bytes) -> tuple[str, str, int, bytes] | None:
    """Return (src_ip, dst_ip, l4_protocol, l4_bytes)."""
    if ethertype == _ETHERTYPE_IPV4:
        if len(data) < 20:
            return None
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None
        proto = data[9]
        src = socket.inet_ntop(socket.AF_INET, data[12:16])
        dst = socket.inet_ntop(socket.AF_INET, data[16:20])
        return src, dst, proto, data[ihl:]

    if ethertype == _ETHERTYPE_IPV6:
        if len(data) < 40:
            return None
        next_header = data[6]
        src = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
        # Only the common case (no extension headers) is decoded; anything else
        # is reported as non-TCP/UDP rather than misparsed.
        return src, dst, next_header, data[40:]

    return None


def _parse_l4(proto: int, data: bytes) -> tuple[str, int, int, bytes] | None:
    if proto == _PROTO_TCP:
        if len(data) < 20:
            return None
        sport, dport = struct.unpack(">HH", data[0:4])
        offset = ((data[12] >> 4) & 0x0F) * 4
        if offset < 20:
            return None
        return "tcp", sport, dport, data[offset:] if len(data) >= offset else b""

    if proto == _PROTO_UDP:
        if len(data) < 8:
            return None
        sport, dport = struct.unpack(">HH", data[0:4])
        return "udp", sport, dport, data[8:]

    return None


def iter_packets(path: Path, start_time: float | None = None, end_time: float | None = None):
    """Yield Packet for every TCP/UDP frame in a pcap file.

    Streams the file rather than loading it, because a capture on a busy host
    can reach hundreds of megabytes and this parser must be able to run against
    a capture that is still being written. `start_time`/`end_time` (epoch
    seconds) slice the file to one scenario window without a second pass.
    """
    with Path(path).open("rb") as source:
        header = source.read(24)
        endian, nanoseconds, linktype, _ = _parse_global_header(header)
        rec_struct = struct.Struct(endian + "IIII")

        while True:
            record = source.read(16)
            if len(record) < 16:
                break  # clean EOF, or a partial record from a live capture
            ts_sec, ts_frac, incl_len, orig_len = rec_struct.unpack(record)
            frame = source.read(incl_len)
            if len(frame) < incl_len:
                break  # truncated final record (capture still running)

            timestamp = ts_sec + (ts_frac / 1_000_000_000 if nanoseconds else ts_frac / 1_000_000)
            if start_time is not None and timestamp < start_time:
                continue
            if end_time is not None and timestamp > end_time:
                break  # records are chronological; nothing later can qualify

            stripped = _strip_link_layer(frame, linktype)
            if stripped is None:
                continue
            ip = _parse_ip(stripped[0], stripped[1])
            if ip is None:
                continue
            src_ip, dst_ip, proto, l4_bytes = ip
            l4 = _parse_l4(proto, l4_bytes)
            if l4 is None:
                continue
            name, sport, dport, payload = l4

            yield Packet(
                timestamp=timestamp,
                protocol=name,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                payload=payload,
                truncated=incl_len < orig_len,
            )


# --------------------------------------------------------------------------
# DNS query names (cross-check only; resolvectl monitor is the primary DNS
# source for this rung because DNS here is routed via a VPN resolver and is not
# necessarily visible in plaintext on the wire).
# --------------------------------------------------------------------------

def parse_dns_question(payload: bytes) -> tuple[str, int] | None:
    """Return (qname, qtype) from a DNS message's first question, or None."""
    if len(payload) < 12:
        return None
    qdcount = struct.unpack(">H", payload[4:6])[0]
    if qdcount < 1:
        return None

    labels: list[str] = []
    pos = 12
    while pos < len(payload):
        length = payload[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0:  # compression pointer: never valid in a question name
            return None
        pos += 1
        if pos + length > len(payload):
            return None
        labels.append(payload[pos : pos + length].decode("ascii", errors="replace"))
        pos += length
    else:
        return None

    if not labels or pos + 2 > len(payload):
        return None
    qtype = struct.unpack(">H", payload[pos : pos + 2])[0]
    return ".".join(labels), qtype


# --------------------------------------------------------------------------
# TLS ClientHello SNI
# --------------------------------------------------------------------------

def parse_tls_client_hello_sni(payload: bytes) -> str | None:
    """Extract the SNI host_name from a TLS ClientHello, or None.

    Returns None (never a partial guess) when the record is not a ClientHello,
    or when a small capture snaplen truncated the buffer before the SNI
    extension was reached.
    """
    try:
        if len(payload) < 5 or payload[0] != 0x16:  # not a handshake record
            return None
        pos = 5
        if len(payload) < pos + 4 or payload[pos] != 0x01:  # not client_hello
            return None
        pos += 4
        pos += 2 + 32  # client_version + random
        if len(payload) < pos + 1:
            return None
        pos += 1 + payload[pos]  # session_id
        if len(payload) < pos + 2:
            return None
        pos += 2 + struct.unpack(">H", payload[pos : pos + 2])[0]  # cipher_suites
        if len(payload) < pos + 1:
            return None
        pos += 1 + payload[pos]  # compression_methods
        if len(payload) < pos + 2:
            return None
        ext_total = struct.unpack(">H", payload[pos : pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(payload))

        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack(">HH", payload[pos : pos + 4])
            pos += 4
            if ext_type != 0x0000:  # server_name
                pos += ext_len
                continue
            if pos + 5 > len(payload):
                return None
            # server_name_list length (2), name_type (1), host_name length (2)
            name_len = struct.unpack(">H", payload[pos + 3 : pos + 5])[0]
            start = pos + 5
            if start + name_len > len(payload):
                return None  # truncated by snaplen
            return payload[start : start + name_len].decode("ascii", errors="replace")
    except (struct.error, IndexError):
        return None
    return None


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    flows: dict[tuple, dict] = {}
    dns_names: set[str] = set()
    sni_names: set[str] = set()
    count = 0

    for pkt in iter_packets(args.pcap):
        count += 1
        key = (pkt.protocol, pkt.dst_ip, pkt.dst_port)
        entry = flows.setdefault(key, {"first": pkt.timestamp, "last": pkt.timestamp, "packets": 0})
        entry["last"] = pkt.timestamp
        entry["packets"] += 1

        if pkt.protocol == "udp" and 53 in (pkt.src_port, pkt.dst_port):
            question = parse_dns_question(pkt.payload)
            if question:
                dns_names.add(question[0])
        elif pkt.protocol == "tcp" and pkt.payload:
            sni = parse_tls_client_hello_sni(pkt.payload)
            if sni:
                sni_names.add(sni)

    print(json.dumps({
        "packets": count,
        "distinct_destinations": len(flows),
        "dns_names": sorted(dns_names),
        "sni_names": sorted(sni_names),
    }, indent=2))
