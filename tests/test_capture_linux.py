"""Tests for the P0-C1 passive-capture tooling.

Every fixture here is synthetic: hand-built pcap bytes, invented hostnames, and
documentation-range addresses (RFC 5737 / RFC 3849). No real capture, real
address, or real account identifier appears in this file.
"""

import struct
import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools" / "capture" / "linux"
sys.path.insert(0, str(TOOLS_DIR))

import build_topology  # noqa: E402
import dns_monitor  # noqa: E402
import pcap_parse  # noqa: E402
import socket_poller  # noqa: E402


# --------------------------------------------------------------------------
# Synthetic pcap construction helpers
# --------------------------------------------------------------------------

def _pcap_bytes(linktype: int, packets: list[bytes]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for index, frame in enumerate(packets):
        out += struct.pack("<IIII", 1_700_000_000 + index, 500000, len(frame), len(frame))
        out += frame
    return out


def _ipv4_tcp(src: str, dst: str, sport: int, dport: int, payload: bytes = b"") -> bytes:
    import socket as s

    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x18, 0, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0, 64, 6, 0)
    ip += s.inet_aton(src) + s.inet_aton(dst)
    return ip + tcp


def _ipv4_udp(src: str, dst: str, sport: int, dport: int, payload: bytes = b"") -> bytes:
    import socket as s

    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0, 64, 17, 0)
    ip += s.inet_aton(src) + s.inet_aton(dst)
    return ip + udp


def _ethernet(inner: bytes) -> bytes:
    return b"\x00" * 6 + b"\x11" * 6 + struct.pack(">H", 0x0800) + inner


def _sll2(inner: bytes) -> bytes:
    return struct.pack(">HHIHBB", 0x0800, 0, 3, 1, 0, 6) + b"\x00" * 8 + inner


def _client_hello(hostname: str) -> bytes:
    host = hostname.encode()
    sni_ext = struct.pack(">HHHBH", 0x0000, len(host) + 5, len(host) + 3, 0, len(host)) + host
    body = (
        struct.pack(">H", 0x0303)
        + b"\x00" * 32          # random
        + b"\x00"               # session_id length
        + struct.pack(">H", 2) + b"\x13\x01"   # cipher suites
        + b"\x01\x00"           # compression methods
        + struct.pack(">H", len(sni_ext)) + sni_ext
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def _dns_query(name: str) -> bytes:
    payload = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        payload += bytes([len(label)]) + label.encode()
    return payload + b"\x00" + struct.pack(">HH", 1, 1)


# --------------------------------------------------------------------------
# pcap parsing
# --------------------------------------------------------------------------

def test_pcap_parses_ethernet_tcp(tmp_path: Path) -> None:
    path = tmp_path / "eth.pcap"
    path.write_bytes(_pcap_bytes(pcap_parse.LINKTYPE_ETHERNET, [
        _ethernet(_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)),
    ]))
    packets = list(pcap_parse.iter_packets(path))
    assert len(packets) == 1
    assert (packets[0].protocol, packets[0].src_ip, packets[0].dst_ip, packets[0].dst_port) == (
        "tcp", "192.0.2.10", "198.51.100.20", 443,
    )


def test_pcap_parses_linux_sll2_used_by_capture_on_any_interface(tmp_path: Path) -> None:
    # `tcpdump -i any` writes SLL2, not Ethernet; misreading it would silently
    # drop every packet in a real capture.
    path = tmp_path / "sll2.pcap"
    path.write_bytes(_pcap_bytes(pcap_parse.LINKTYPE_LINUX_SLL2, [
        _sll2(_ipv4_udp("192.0.2.10", "198.51.100.53", 40000, 53, _dns_query("example.invalid"))),
    ]))
    packets = list(pcap_parse.iter_packets(path))
    assert len(packets) == 1
    assert packets[0].protocol == "udp" and packets[0].dst_port == 53


def test_pcap_dns_question_extraction(tmp_path: Path) -> None:
    path = tmp_path / "dns.pcap"
    path.write_bytes(_pcap_bytes(pcap_parse.LINKTYPE_LINUX_SLL2, [
        _sll2(_ipv4_udp("192.0.2.10", "198.51.100.53", 40000, 53, _dns_query("svc.example.invalid"))),
    ]))
    packet = next(iter(pcap_parse.iter_packets(path)))
    assert pcap_parse.parse_dns_question(packet.payload) == ("svc.example.invalid", 1)


def test_tls_sni_extracted_from_client_hello() -> None:
    assert pcap_parse.parse_tls_client_hello_sni(_client_hello("title.example.invalid")) == "title.example.invalid"


def test_tls_sni_truncated_by_snaplen_returns_none_not_a_guess() -> None:
    full = _client_hello("title.example.invalid")
    assert pcap_parse.parse_tls_client_hello_sni(full[: len(full) - 8]) is None


def test_tls_sni_ignores_non_handshake_payload() -> None:
    assert pcap_parse.parse_tls_client_hello_sni(b"\x17\x03\x03\x00\x10" + b"\x00" * 16) is None
    assert pcap_parse.parse_tls_client_hello_sni(b"") is None


# --------------------------------------------------------------------------
# resolvectl monitor parsing
# --------------------------------------------------------------------------

def test_dns_monitor_parses_transactions_and_address_map(tmp_path: Path) -> None:
    log = tmp_path / "dns.log"
    log.write_text(
        "1700000000.100000\t→ Q: svc.example.invalid IN A\n"
        "1700000000.200000\t← S: success\n"
        "1700000000.300000\t← A: svc.example.invalid IN A 198.51.100.7\n"
        "1700000000.400000\t\n"
        "1700000001.000000\t→ Q: other.example.invalid IN AAAA\n"
        "1700000001.100000\t← S: NXDOMAIN\n",
        encoding="utf-8",
    )
    transactions = dns_monitor.parse_monitor_log(log)
    assert len(transactions) == 2
    assert transactions[0].query_names == ["svc.example.invalid"]
    assert transactions[0].status == "success"
    assert transactions[1].status == "NXDOMAIN"
    assert dns_monitor.address_to_names(transactions)["198.51.100.7"] == {"svc.example.invalid"}


def test_dns_monitor_blank_line_separates_transactions(tmp_path: Path) -> None:
    log = tmp_path / "dns.log"
    log.write_text(
        "1700000000.0\t→ Q: a.example.invalid IN A\n"
        "1700000000.1\t\n"
        "1700000000.2\t→ Q: b.example.invalid IN A\n",
        encoding="utf-8",
    )
    assert [t.query_names for t in dns_monitor.parse_monitor_log(log)] == [
        ["a.example.invalid"], ["b.example.invalid"],
    ]


# --------------------------------------------------------------------------
# ss parsing
# --------------------------------------------------------------------------

def test_ss_parses_ipv4_with_process() -> None:
    row = socket_poller.parse_ss_line(
        'tcp   ESTAB 0 0   192.0.2.10:60191   198.51.100.31:27036 users:(("steam",pid=4306,fd=133))'
    )
    assert row is not None
    netid, state, local, peer, processes = row
    assert (netid, state) == ("tcp", "ESTAB")
    assert (peer.address, peer.port) == ("198.51.100.31", 27036)
    assert processes == {("steam", 4306)}


def test_ss_parses_bracketed_ipv6_and_multiple_processes() -> None:
    row = socket_poller.parse_ss_line(
        'tcp ESTAB 0 0 [2001:db8::1]:443 [2001:db8::2]:51000 users:(("a",pid=1,fd=2),("b",pid=3,fd=4))'
    )
    assert row is not None
    assert row[3].address == "2001:db8::2"
    assert row[4] == {("a", 1), ("b", 3)}


def test_ss_strips_interface_scope_and_tolerates_missing_process() -> None:
    row = socket_poller.parse_ss_line("udp ESTAB 0 0 192.0.2.10%wlan0:68 192.0.2.1:67")
    assert row is not None
    assert row[2].address == "192.0.2.10"
    assert row[4] == set()


def test_ss_rejects_malformed_rows() -> None:
    assert socket_poller.parse_ss_line("") is None
    assert socket_poller.parse_ss_line("garbage") is None


# --------------------------------------------------------------------------
# Classification rules
# --------------------------------------------------------------------------

def test_process_role_matching_handles_kernel_comm_truncation() -> None:
    # `ss` reports comm truncated to 15 chars: "MCC-Win64-Shipping.exe" arrives as "MCC-Win64-Shipp".
    assert build_topology.role_for_process("MCC-Win64-Shipp") == "mcc_game"
    assert build_topology.role_for_process("wineserver") == "proton_wine"
    assert build_topology.role_for_process("steamwebhelper") == "steam_client"
    assert build_topology.role_for_process("some-unrelated-app") is None


def test_game_role_survives_main_thread_comm_rename() -> None:
    # The kernel reports the main THREAD name in `comm`, and the game renames
    # its main thread to MAIN_THREAD after startup. Attribution keyed on comm
    # alone silently loses the game's own sockets once it is running.
    assert build_topology.role_for_process("MAIN_THREAD") is None
    args = r"S:\common\Halo The Master Chief Collection\MCC\Binaries\Win64\MCC-Win64-Shipping.exe"
    assert build_topology.role_from_args(args) == "mcc_game"

    pid_roles = {295043: "mcc_game"}
    assert build_topology.resolve_roles({("MAIN_THREAD", 295043)}, pid_roles) == {"mcc_game"}
    # Without the PID map the same socket would resolve to nothing.
    assert build_topology.resolve_roles({("MAIN_THREAD", 295043)}, {}) == set()


def test_wrapper_chain_is_not_mislabelled_as_the_game() -> None:
    # Every wrapper carries the launched executable's path in its own argv.
    reaper = (
        "/steam/ubuntu12_32/reaper SteamLaunch AppId=976730 -- "
        "/steam/steamapps/common/Proton - Experimental/proton waitforexitandrun "
        "/steam/steamapps/common/Halo The Master Chief Collection/mcclauncher.exe"
    )
    assert build_topology.role_from_args(reaper) == "proton_wine"
    assert build_topology.role_from_args("wineserver") == "proton_wine"
    assert build_topology.role_from_args("some-unrelated-daemon --serve") is None


def test_pid_args_timeline_builds_pid_role_map(tmp_path: Path) -> None:
    timeline = tmp_path / "pid_args.txt"
    timeline.write_text(
        "=== t=1700000000.0 ===\n"
        " 295043 MAIN_THREAD     "
        r"S:\common\Halo The Master Chief Collection\MCC\Binaries\Win64\MCC-Win64-Shipping.exe"
        "\n"
        " 294930 wineserver      /steam/common/Proton - Experimental/files/bin/wineserver\n"
        " 4306 steam            /steam/ubuntu12_32/steam -silent\n",
        encoding="utf-8",
    )
    pid_roles = build_topology.parse_pid_args_timeline(timeline)
    assert pid_roles[295043] == "mcc_game"
    assert pid_roles[294930] == "proton_wine"
    assert pid_roles[4306] == "steam_client"


def test_family_matching_requires_registrable_suffix_not_substring() -> None:
    assert build_topology.family_for_host("user.auth.xboxlive.com") == "xbox_platform"
    assert build_topology.family_for_host("XBOXLIVE.COM") == "xbox_platform"
    # A lookalike that merely contains a known name must not match.
    assert build_topology.family_for_host("xboxlive.com.attacker.invalid") is None
    assert build_topology.family_for_host("notsteampowered.com") is None


def test_confirmed_requires_both_process_attribution_and_family() -> None:
    confirmed = build_topology.Endpoint(
        peer_address="198.51.100.5", peer_port=443, protocol="tcp",
        hostnames={"user.auth.xboxlive.com"}, roles={"mcc_game"},
    )
    classification, reason = confirmed.classify()
    assert classification == "Confirmed Xbox platform"
    assert "mcc_game" in reason and "xbox_platform" in reason


def test_family_match_without_process_attribution_is_only_likely() -> None:
    endpoint = build_topology.Endpoint(
        peer_address="198.51.100.5", peer_port=443, protocol="tcp",
        hostnames={"user.auth.xboxlive.com"}, roles=set(),
    )
    classification, reason = endpoint.classify()
    assert classification == "Likely classification requiring verification"
    assert "not sufficient to confirm" in reason


def test_unnamed_endpoint_is_unknown() -> None:
    endpoint = build_topology.Endpoint(
        peer_address="198.51.100.9", peer_port=3074, protocol="udp", roles={"mcc_game"},
    )
    classification, reason = endpoint.classify()
    assert classification == "Unknown"
    assert "no DNS/SNI name" in reason


def test_shared_ip_prefers_service_family_over_cdn() -> None:
    # One edge IP can serve both a title service and a CDN name; reporting it as
    # CDN/telemetry would discard the more informative fact.
    endpoint = build_topology.Endpoint(
        peer_address="198.51.100.12", peer_port=443, protocol="tcp",
        hostnames={"gamecms.svc.halowaypoint.com", "assets.akamaized.net"},
        roles={"mcc_game"},
    )
    assert endpoint.classify()[0] == "Confirmed MCC/Halo title service"


def test_title_specific_frontdoor_host_matches_but_generic_suffix_does_not() -> None:
    assert build_topology.family_for_host("mcc-production.azurefd.net") == "halo_title"
    # A generic Azure Front Door tenant must not inherit the title family.
    assert build_topology.family_for_host("someoneelse.azurefd.net") is None


def test_playfab_is_only_likely_not_confirmed() -> None:
    # A shared multi-tenant backend is not self-evidently a title service.
    endpoint = build_topology.Endpoint(
        peer_address="198.51.100.13", peer_port=443, protocol="tcp",
        hostnames={"ee38.playfabapi.com"}, roles={"mcc_game"},
    )
    assert endpoint.classify()[0] == "Likely classification requiring verification"


def test_cdn_classification_does_not_claim_a_service_layer() -> None:
    endpoint = build_topology.Endpoint(
        peer_address="198.51.100.11", peer_port=443, protocol="tcp",
        hostnames={"assets.akamaized.net"}, roles={"mcc_game"},
    )
    assert endpoint.classify()[0] == "CDN/telemetry"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
