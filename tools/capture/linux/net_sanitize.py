"""Network-evidence sanitization for committed P0-C1 outputs.

Extends the path/account redaction in `tools/inventory/linux/sanitize.py` with
address- and network-identity redaction, and derives every value from the live
host rather than from hardcoded literals, so a real address never has to appear
in a command line or in this source file.

Redaction policy, by address class:

- This host's own addresses      -> `<LOCAL_IPV4>` / `<LOCAL_IPV6>` (and
                                    `<TAILSCALE_IPV4>` / `<TAILSCALE_IPV6>` for
                                    the VPN interface)
- Other private/CGNAT/link-local -> `<PRIVATE_HOST_n>`, numbered in sorted order
                                    (LAN neighbours and tailnet peers are other
                                    people's/devices' addresses, not evidence
                                    about MCC)
- Loopback                       -> kept as-is (universal, not identifying)
- Public addresses               -> **kept**, because a destination server's
                                    address is the evidence this rung exists to
                                    record, and is not personal data

Also redacts the tailnet search domain and tailnet device hostnames, which are
private infrastructure names unrelated to MCC.

The numbering of `<PRIVATE_HOST_n>` is stable within one run (sorted order). The
mapping is never committed, so the placeholders are not reversible from the
repository.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path

_INVENTORY_TOOLS = Path(__file__).resolve().parents[2] / "inventory" / "linux"
if str(_INVENTORY_TOOLS) not in sys.path:
    sys.path.insert(0, str(_INVENTORY_TOOLS))

from sanitize import Sanitizer  # noqa: E402  (path set above)

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")


def host_addresses() -> set[str]:
    """Every IP address currently assigned to this host, from `ip -json addr`."""
    try:
        result = subprocess.run(["ip", "-json", "addr"], capture_output=True, text=True, timeout=10, check=False)
        payload = json.loads(result.stdout or "[]")
    except (json.JSONDecodeError, OSError, subprocess.SubprocessError):
        return set()
    addresses = set()
    for link in payload:
        for info in link.get("addr_info", []):
            if info.get("local"):
                addresses.add(info["local"])
    return addresses


def tailscale_identity() -> tuple[set[str], set[str]]:
    """Return (tailnet addresses, tailnet device hostnames), empty if unavailable."""
    addresses: set[str] = set()
    names: set[str] = set()
    try:
        result = subprocess.run(
            ["tailscale", "status", "--json"], capture_output=True, text=True, timeout=10, check=False
        )
        payload = json.loads(result.stdout or "{}")
    except (json.JSONDecodeError, OSError, subprocess.SubprocessError):
        return addresses, names

    def absorb(peer: dict) -> None:
        for address in peer.get("TailscaleIPs") or []:
            addresses.add(address)
        for key in ("HostName", "DNSName"):
            value = peer.get(key)
            if value:
                names.add(value.rstrip(".").split(".")[0])
                if key == "DNSName":
                    names.add(value.rstrip("."))

    if isinstance(payload.get("Self"), dict):
        absorb(payload["Self"])
    for peer in (payload.get("Peer") or {}).values():
        if isinstance(peer, dict):
            absorb(peer)
    return addresses, names


def search_domains() -> set[str]:
    """DNS search domains (e.g. a private tailnet domain) from resolvectl."""
    domains: set[str] = set()
    try:
        result = subprocess.run(["resolvectl", "domain"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return domains
    for token in re.split(r"[\s,]+", result.stdout or ""):
        token = token.strip().lstrip("~").rstrip(".")
        if token and "." in token and not token.startswith("("):
            domains.add(token)
    return domains


def _classify(address: str, local: set[str], tailnet: set[str]) -> str | None:
    """Return a placeholder for an address needing redaction, else None to keep it."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
        return None
    is_v6 = parsed.version == 6
    if address in tailnet:
        return "<TAILSCALE_IPV6>" if is_v6 else "<TAILSCALE_IPV4>"
    if address in local:
        return "<LOCAL_IPV6>" if is_v6 else "<LOCAL_IPV4>"
    # 100.64.0.0/10 (CGNAT, used by tailscale) counts as private for our purposes.
    in_cgnat = parsed.version == 4 and parsed in ipaddress.ip_network("100.64.0.0/10")
    if parsed.is_private or parsed.is_link_local or in_cgnat:
        return "PRIVATE"  # caller assigns a stable index
    return None


class NetworkSanitizer:
    """Sanitizes paths, accounts, addresses, and private network names."""

    def __init__(self, appid: str = "976730", install_dir_name: str = "Halo The Master Chief Collection"):
        home_raw = str(Path.home())
        home_variants = [home_raw, os.path.realpath(home_raw)]
        steam_library = [f"{h}/.local/share/Steam" for h in home_variants]
        install_root = f"{os.path.realpath(home_raw)}/.local/share/Steam/steamapps/common/{install_dir_name}"
        prefix = [f"{lib}/steamapps/compatdata/{appid}/pfx" for lib in steam_library]

        steam_root = Path(os.path.realpath(home_raw)) / ".local" / "share" / "Steam"
        userdata = steam_root / "userdata"
        account_ids = sorted(p.name for p in userdata.iterdir() if p.is_dir() and p.name.isdigit()) if userdata.is_dir() else []

        self._paths = Sanitizer(
            mcc_install_root=install_root,
            home=home_variants,
            steam_account_ids=account_ids,
            proton_prefix=prefix,
            steam_library=steam_library,
            account_id_placeholder="<ACCOUNT_IDENTIFIER_REDACTED>",
        )

        self._local = host_addresses()
        self._tailnet_addresses, self._tailnet_names = tailscale_identity()
        self._domains = search_domains()
        self._private_index: dict[str, str] = {}

    def _placeholder_for(self, address: str) -> str | None:
        verdict = _classify(address, self._local, self._tailnet_addresses)
        if verdict is None:
            return None
        if verdict != "PRIVATE":
            return verdict
        if address not in self._private_index:
            self._private_index[address] = f"<PRIVATE_HOST_{len(self._private_index) + 1}>"
        return self._private_index[address]

    def address(self, value: str) -> str:
        return self._placeholder_for(value) or value

    def text(self, value: str) -> str:
        out = self._paths.text(value)
        for name in sorted(self._tailnet_names, key=len, reverse=True):
            if name:
                out = re.sub(rf"\b{re.escape(name)}\b", "<TAILNET_HOST>", out)
        for domain in sorted(self._domains, key=len, reverse=True):
            out = re.sub(rf"\b{re.escape(domain)}\b", "<TAILNET_DOMAIN>", out)

        def swap(match: re.Match) -> str:
            return self._placeholder_for(match.group(0)) or match.group(0)

        out = _IPV4_RE.sub(swap, out)
        return _IPV6_RE.sub(swap, out)

    def value(self, obj):
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {self.value(k): self.value(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.value(v) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self.value(v) for v in obj)
        return obj


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=None)
    args = parser.parse_args()

    sanitizer = NetworkSanitizer()
    text = sanitizer.text(args.input.read_text(encoding="utf-8", errors="replace"))
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote sanitized text to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
