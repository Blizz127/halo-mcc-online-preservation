"""Merge DNS, socket, and pcap evidence into a classified connection topology.

Join model
----------
A socket flow is attributed to a hostname by matching its **peer address**
against an address that DNS actually returned during the capture. Reverse DNS is
never used for attribution: `docs/EVIDENCE_POLICY.md` treats a name alone as
insufficient, and a PTR record describes address ownership, not application
purpose.

Privacy filter
--------------
`resolvectl monitor` observes DNS for the entire host, which includes unrelated
applications (browser, chat, sync clients). Only flows attributed to a target
process role — the MCC game, its launcher, the Proton/Wine layer, or the Steam
client — are retained for the committed inventories. Everything else is counted
and reported as an excluded total, never enumerated, so the committed evidence
cannot become a record of unrelated browsing.

Classification
--------------
A `Confirmed` classification requires **both** process attribution to a relevant
role **and** a registrable-domain match against a known service family, plus the
supporting reason recorded alongside it. A family match without process
attribution is at most `Likely`. No endpoint is ever confirmed on hostname alone.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path

import dns_monitor
import socket_poller

# --------------------------------------------------------------------------
# Process roles. `ss` reports `comm`, truncated to 15 characters by the kernel,
# so these are matched as prefixes rather than exact names.
# --------------------------------------------------------------------------

ROLE_PREFIXES: dict[str, tuple[str, ...]] = {
    "mcc_game": ("MCC-Win64-Shipp",),
    "mcc_launcher": ("mcclauncher",),
    "proton_wine": (
        "wineserver", "winedevice", "steam.exe", "xalia", "pressure-vessel",
        "pv-adverb", "srt-bwrap", "reaper", "explorer.exe", "services.exe",
        "rpcss.exe", "plugplay.exe", "winemenubuilder",
    ),
    "steam_client": (
        "steam", "steamwebhelper", "steam-runtime", "gameoverlayui", "bazzite-steam",
    ),
}

# Roles whose traffic is retained in committed evidence.
TARGET_ROLES = ("mcc_game", "mcc_launcher", "proton_wine", "steam_client")

# --------------------------------------------------------------------------
# Service families. These are ONE input to classification, never sufficient
# alone. Matching is on the registrable domain suffix.
# --------------------------------------------------------------------------

SERVICE_FAMILIES: dict[str, tuple[str, ...]] = {
    "valve_steam": (
        "steampowered.com", "steamcommunity.com", "steamstatic.com",
        "steamcontent.com", "steamserver.net", "steamusercontent.com",
        "valvesoftware.com", "steamgames.com", "steam-chat.com",
    ),
    "microsoft_identity": (
        "login.live.com", "login.microsoftonline.com", "account.live.com",
        "msftauth.net", "msauth.net", "live.com", "microsoftonline.com",
    ),
    "xbox_platform": (
        "xboxlive.com", "xboxservices.com", "xbox.com", "xboxab.com",
    ),
    "halo_title": (
        "halowaypoint.com", "343industries.com", "halo.com",
        # Title-specific Azure Front Door hostname. Listed as a full hostname,
        # not by its `azurefd.net` suffix, which is generic Microsoft edge
        # infrastructure shared by unrelated tenants.
        "mcc-production.azurefd.net",
    ),
    "microsoft_playfab": (
        "playfabapi.com",
    ),
    "epic_eos": (
        "epicgames.com", "epicgames.dev", "unrealengine.com", "easyanticheat.net",
    ),
    "cdn_telemetry": (
        "akamaized.net", "akamai.net", "akamaiedge.net", "cloudfront.net",
        "azureedge.net", "msedge.net", "data.microsoft.com", "events.data.microsoft.com",
        "trafficmanager.net", "edgesuite.net", "llnwd.net", "fastly.net",
    ),
}

CLASSIFICATION_BY_FAMILY = {
    "valve_steam": "Confirmed Steam",
    "microsoft_identity": "Confirmed Microsoft identity",
    "xbox_platform": "Confirmed Xbox platform",
    "halo_title": "Confirmed MCC/Halo title service",
    # PlayFab is Microsoft's multi-tenant game backend. The title-specific
    # hostname prefix suggests an MCC tenant, but a shared backend is not
    # self-evidently a title service, so it stays unconfirmed by design.
    "microsoft_playfab": "Likely classification requiring verification",
    "epic_eos": "Likely classification requiring verification",
    "cdn_telemetry": "CDN/telemetry",
}

# One address can serve several names (shared edge infrastructure). When that
# happens, the most service-specific family wins: reporting a title service as
# "CDN/telemetry" purely because a CDN name shares its IP would lose the more
# informative fact.
_FAMILY_PRIORITY = (
    "halo_title", "xbox_platform", "microsoft_identity", "valve_steam",
    "microsoft_playfab", "epic_eos", "cdn_telemetry",
)


def role_for_process(comm: str) -> str | None:
    for role, prefixes in ROLE_PREFIXES.items():
        for prefix in prefixes:
            if comm.startswith(prefix[:15]):
                return role
    return None


# Wrapper/launch-chain markers. Every layer between Steam and the game carries
# the launched executable's path in its own argv, so a naive substring test on
# argv would label the whole chain as the game. These markers identify a process
# as a wrapper so it is classified by what it *is*, not by what it launches.
_WRAPPER_MARKERS = (
    "proton", "reaper", "srt-bwrap", "pv-adverb", "pressure-vessel",
    "_v2-entry-point", "wineserver", "winedevice", "xalia", "steam.exe",
)


def role_from_args(args: str) -> str | None:
    """Derive a process role from full argv.

    Required because `comm` is not stable for the game itself: the kernel
    reports the main *thread* name, and MCC-Win64-Shipping.exe renames its main
    thread to `MAIN_THREAD` shortly after startup. Attribution keyed on `comm`
    alone therefore silently loses the game's own sockets once it is running —
    which would drop exactly the traffic this rung exists to record.
    """
    if not args:
        return None
    lowered = args.lower()
    is_wrapper = any(marker in lowered for marker in _WRAPPER_MARKERS)

    if "mcc-win64-shipping.exe" in lowered and not is_wrapper:
        return "mcc_game"
    if "mcclauncher.exe" in lowered and not is_wrapper:
        return "mcc_launcher"
    if is_wrapper:
        return "proton_wine"
    if "ubuntu12_32/steam" in lowered or "steamwebhelper" in lowered or "gameoverlayui" in lowered:
        return "steam_client"
    return None


def parse_pid_args_timeline(path: Path) -> dict[int, str]:
    """Build pid -> role from a `ps -eo pid,comm,args` timeline snapshot file."""
    pid_roles: dict[int, str] = {}
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("==="):
            continue
        parts = stripped.split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        pid, comm, args = int(parts[0]), parts[1], parts[2]
        role = role_from_args(args) or role_for_process(comm)
        if role:
            pid_roles[pid] = role
    return pid_roles


def resolve_roles(processes: set[tuple[str, int]], pid_roles: dict[int, str]) -> set[str]:
    """Roles for a socket's owning processes: PID mapping first, `comm` as fallback."""
    roles: set[str] = set()
    for comm, pid in processes:
        role = pid_roles.get(pid) or role_for_process(comm)
        if role:
            roles.add(role)
    return roles


def family_for_host(hostname: str) -> str | None:
    host = hostname.lower().rstrip(".")
    for family, suffixes in SERVICE_FAMILIES.items():
        for suffix in suffixes:
            if host == suffix or host.endswith("." + suffix):
                return family
    return None


@dataclass
class Endpoint:
    peer_address: str
    peer_port: int
    protocol: str
    hostnames: set[str] = field(default_factory=set)
    processes: set[tuple[str, int]] = field(default_factory=set)
    roles: set[str] = field(default_factory=set)
    scenarios: set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    sample_count: int = 0
    sni_names: set[str] = field(default_factory=set)

    def classify(self) -> tuple[str, str]:
        """Return (classification, reason)."""
        families = {f for h in self.hostnames | self.sni_names if (f := family_for_host(h))}
        attributed = bool(self.roles & set(TARGET_ROLES))
        role_list = ",".join(sorted(self.roles)) or "none"
        name_list = ",".join(sorted(self.hostnames | self.sni_names)) or "no-name"

        if not families:
            if not self.hostnames and not self.sni_names:
                return "Unknown", f"no DNS/SNI name resolved to this address; processes={role_list}"
            return "Unknown", f"name(s) {name_list} match no known service family; processes={role_list}"

        family = next((f for f in _FAMILY_PRIORITY if f in families), sorted(families)[0])
        base = CLASSIFICATION_BY_FAMILY[family]

        if base == "CDN/telemetry":
            return base, f"name(s) {name_list} are CDN/telemetry infrastructure; processes={role_list}"

        if not attributed:
            return (
                "Likely classification requiring verification",
                f"name(s) {name_list} match family '{family}' but no target process owned the socket "
                f"(processes={role_list}); a name alone is not sufficient to confirm",
            )

        if base.startswith("Confirmed"):
            return base, f"process role(s) {role_list} owned the socket AND name(s) {name_list} match family '{family}'"
        return base, f"name(s) {name_list} match family '{family}'; processes={role_list}"


def load_scenarios(index_path: Path) -> list[dict]:
    return json.loads(Path(index_path).read_text(encoding="utf-8"))["scenarios"]


def _window(scenario: dict) -> tuple[float | None, float | None]:
    return scenario.get("start_epoch"), scenario.get("end_epoch")


def _in_window(timestamp: float, window: tuple[float | None, float | None]) -> bool:
    start, end = window
    if start is not None and timestamp < start:
        return False
    if end is not None and timestamp > end:
        return False
    return True


def _overlaps(first_seen: float, last_seen: float, window: tuple[float | None, float | None]) -> bool:
    """True when a flow's lifetime intersects the scenario window at all."""
    start, end = window
    if start is not None and last_seen < start:
        return False
    if end is not None and first_seen > end:
        return False
    return True


def build(scenarios: list[dict], scratch: Path, pid_roles: dict[int, str] | None = None) -> tuple[dict[tuple, Endpoint], dict]:
    """Return (endpoints keyed by (proto, addr, port), stats)."""
    pid_roles = pid_roles or {}
    endpoints: dict[tuple, Endpoint] = {}
    stats = {
        "flows_total": 0,
        "flows_attributed_to_target": 0,
        "flows_excluded_other_processes": 0,
        "flows_unattributed": 0,
        "dns_transactions": 0,
        "dns_names_total": 0,
    }

    # Scenarios may share one continuous log, so each is sliced to its own
    # window rather than re-counting the whole file per scenario.
    address_names: dict[str, set[str]] = {}
    seen_dns_logs: set[str] = set()
    for scenario in scenarios:
        dns_log = scratch / scenario["dns_log"]
        if not dns_log.is_file():
            continue
        transactions = dns_monitor.parse_monitor_log(dns_log)
        window = _window(scenario)
        scoped = [t for t in transactions if _in_window(t.first_seen, window)]
        if str(dns_log) not in seen_dns_logs:
            seen_dns_logs.add(str(dns_log))
            stats["dns_transactions"] += len(transactions)
        # Address->name mapping is global on purpose: a name resolved in one
        # scenario may be connected to in a later one.
        for address, names in dns_monitor.address_to_names(scoped or transactions).items():
            address_names.setdefault(address, set()).update(names)
    stats["dns_names_total"] = len({n for names in address_names.values() for n in names})

    for scenario in scenarios:
        flow_file = scratch / scenario["flow_log"]
        if not flow_file.is_file():
            continue
        window = _window(scenario)
        for record in socket_poller.read_flows_jsonl(flow_file):
            if not _overlaps(record.get("first_seen", 0.0), record.get("last_seen", 0.0), window):
                continue
            stats["flows_total"] += 1
            processes = {(p[0], int(p[1])) for p in record.get("processes", [])}
            roles = resolve_roles(processes, pid_roles)

            if not processes:
                stats["flows_unattributed"] += 1
            if not (roles & set(TARGET_ROLES)):
                if processes:
                    stats["flows_excluded_other_processes"] += 1
                    continue  # unrelated application: never enumerated
                # Unattributed flows are kept only so they can be reported as unresolved.
            else:
                stats["flows_attributed_to_target"] += 1

            key = (record["netid"], record["peer_address"], record["peer_port"])
            endpoint = endpoints.get(key)
            if endpoint is None:
                endpoint = Endpoint(
                    peer_address=record["peer_address"],
                    peer_port=record["peer_port"],
                    protocol=record["netid"],
                    first_seen=record["first_seen"],
                    last_seen=record["last_seen"],
                )
                endpoints[key] = endpoint
            endpoint.processes.update(processes)
            endpoint.roles.update(roles)
            endpoint.scenarios.add(scenario["id"])
            endpoint.first_seen = min(endpoint.first_seen, record["first_seen"])
            endpoint.last_seen = max(endpoint.last_seen, record["last_seen"])
            endpoint.sample_count += record.get("sample_count", 0)
            endpoint.hostnames.update(address_names.get(record["peer_address"], set()))

    return endpoints, stats


def attach_sni(endpoints: dict[tuple, Endpoint], pcap_path: Path) -> dict:
    """Fold TLS SNI and pcap-observed DNS into endpoints. Returns pcap stats."""
    import pcap_parse

    pcap_stats = {"packets": 0, "sni_observed": 0, "dns_questions": 0, "truncated_packets": 0}
    if not pcap_path or not Path(pcap_path).is_file():
        return pcap_stats

    by_address: dict[str, list[Endpoint]] = {}
    for endpoint in endpoints.values():
        by_address.setdefault(endpoint.peer_address, []).append(endpoint)

    for packet in pcap_parse.iter_packets(pcap_path):
        pcap_stats["packets"] += 1
        if packet.truncated:
            pcap_stats["truncated_packets"] += 1
        if packet.protocol == "udp" and 53 in (packet.src_port, packet.dst_port):
            if pcap_parse.parse_dns_question(packet.payload):
                pcap_stats["dns_questions"] += 1
            continue
        if packet.protocol == "tcp" and packet.payload:
            sni = pcap_parse.parse_tls_client_hello_sni(packet.payload)
            if sni:
                pcap_stats["sni_observed"] += 1
                for endpoint in by_address.get(packet.dst_ip, []):
                    endpoint.sni_names.add(sni)
    return pcap_stats


# --------------------------------------------------------------------------
# Emitters
# --------------------------------------------------------------------------

def write_domain_inventory(endpoints: dict[tuple, Endpoint], path: Path, sanitizer) -> int:
    rows: dict[str, dict] = {}
    for endpoint in endpoints.values():
        classification, reason = endpoint.classify()
        for hostname in sorted(endpoint.hostnames | endpoint.sni_names):
            row = rows.setdefault(hostname, {
                "hostname": hostname,
                "classification": classification,
                "family": family_for_host(hostname) or "",
                "protocols": set(),
                "ports": set(),
                "roles": set(),
                "scenarios": set(),
                "observed_via_sni": hostname in endpoint.sni_names,
                "reason": reason,
            })
            row["protocols"].add(endpoint.protocol)
            row["ports"].add(str(endpoint.peer_port))
            row["roles"].update(endpoint.roles)
            row["scenarios"].update(endpoint.scenarios)

    with Path(path).open("w", newline="", encoding="utf-8") as sink:
        # csv defaults to CRLF; force LF so committed files stay clean under
        # `git diff --check`.
        writer = csv.writer(sink, lineterminator="\n")
        writer.writerow([
            "hostname", "classification", "service_family", "protocols", "ports",
            "process_roles", "scenarios", "observed_via_tls_sni", "classification_reason",
        ])
        for hostname in sorted(rows):
            row = rows[hostname]
            writer.writerow([
                hostname, row["classification"], row["family"],
                "|".join(sorted(row["protocols"])), "|".join(sorted(row["ports"], key=int)),
                "|".join(sorted(row["roles"])) or "unattributed",
                "|".join(sorted(row["scenarios"])),
                "yes" if row["observed_via_sni"] else "no",
                sanitizer.text(row["reason"]),
            ])
    return len(rows)


def write_flow_inventory(endpoints: dict[tuple, Endpoint], path: Path, sanitizer) -> int:
    with Path(path).open("w", newline="", encoding="utf-8") as sink:
        writer = csv.writer(sink, lineterminator="\n")
        writer.writerow([
            "protocol", "peer_address", "peer_port", "hostnames", "classification",
            "process_roles", "process_names", "scenarios", "samples",
            "first_seen_offset_s", "duration_s",
        ])
        if not endpoints:
            return 0
        origin = min(e.first_seen for e in endpoints.values())
        for endpoint in sorted(endpoints.values(), key=lambda e: (e.first_seen, e.peer_address)):
            classification, _ = endpoint.classify()
            writer.writerow([
                endpoint.protocol,
                sanitizer.address(endpoint.peer_address),
                endpoint.peer_port,
                "|".join(sorted(endpoint.hostnames | endpoint.sni_names)),
                classification,
                "|".join(sorted(endpoint.roles)) or "unattributed",
                "|".join(sorted({c for c, _ in endpoint.processes})) or "none",
                "|".join(sorted(endpoint.scenarios)),
                endpoint.sample_count,
                f"{endpoint.first_seen - origin:.1f}",
                f"{endpoint.last_seen - endpoint.first_seen:.1f}",
            ])
    return len(endpoints)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", type=Path, help="capture index JSON")
    parser.add_argument("scratch", type=Path, help="scratch dir holding dns/flow logs")
    parser.add_argument("outdir", type=Path)
    parser.add_argument("--pcap", type=Path, default=None)
    args = parser.parse_args()

    from net_sanitize import NetworkSanitizer

    scenarios = load_scenarios(args.index)
    endpoints, stats = build(scenarios, args.scratch)
    pcap_stats = attach_sni(endpoints, args.pcap) if args.pcap else {}
    sanitizer = NetworkSanitizer()

    args.outdir.mkdir(parents=True, exist_ok=True)
    domains = write_domain_inventory(endpoints, args.outdir / "domain_inventory.csv", sanitizer)
    flows = write_flow_inventory(endpoints, args.outdir / "flow_inventory.csv", sanitizer)

    print(json.dumps({"domains": domains, "flows": flows, "stats": stats, "pcap": pcap_stats}, indent=2))
