"""Capture-interface discovery, tool versions, and capture-readiness reporting.

Read-only. Reports whether privileged capture is actually available on this host
rather than assuming it: on an ostree-based system `/usr` is read-only, so
`setcap` cannot be applied to `tcpdump` in place, and an unprivileged capture
attempt fails with `CAP_NET_RAW may be required`. Knowing this up front is what
decides whether a rung runs with pcap evidence or with socket/DNS evidence only.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def _run(*cmd: str, timeout: int = 10) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None
    output = (result.stdout or result.stderr or "").strip()
    return output or None


def tool_versions() -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    probes = {
        "tcpdump": ("tcpdump", "--version"),
        "dumpcap": ("dumpcap", "--version"),
        "tshark": ("tshark", "--version"),
        "ss": ("ss", "-V"),
        "lsof": ("lsof", "-v"),
        "ip": ("ip", "-V"),
        "resolvectl": ("resolvectl", "--version"),
        "python3": ("python3", "--version"),
    }
    for name, cmd in probes.items():
        if shutil.which(cmd[0]) is None:
            versions[name] = None
            continue
        output = _run(*cmd)
        versions[name] = output.splitlines()[0].strip() if output else None
    return versions


def interfaces() -> list[dict]:
    """Interfaces with addresses, from `ip -json addr` (no capture required)."""
    raw = _run("ip", "-json", "addr")
    try:
        payload = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    result = []
    for link in payload:
        result.append({
            "name": link.get("ifname"),
            "state": link.get("operstate"),
            "address_families": sorted({a.get("family") for a in link.get("addr_info", []) if a.get("family")}),
            "address_count": len(link.get("addr_info", [])),
        })
    return result


def default_route_interface() -> str | None:
    raw = _run("ip", "route", "show", "default")
    if not raw:
        return None
    for token in raw.split():
        if token == "dev":
            index = raw.split().index("dev")
            parts = raw.split()
            if index + 1 < len(parts):
                return parts[index + 1]
    return None


def dns_servers() -> list[str]:
    """Configured DNS servers, which may differ from the default route's path."""
    raw = _run("resolvectl", "status")
    servers: list[str] = []
    if not raw:
        return servers
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith(("Current DNS Server:", "DNS Servers:")):
            _, _, value = stripped.partition(":")
            servers.extend(v for v in value.split() if v)
    return sorted(set(servers))


def capture_readiness() -> dict:
    """Whether unprivileged packet capture works, and why not when it does not."""
    tcpdump = shutil.which("tcpdump")
    readiness = {
        "tcpdump_path": tcpdump,
        "unprivileged_capture_works": False,
        "detail": None,
        "usr_writable": None,
    }
    if tcpdump is None:
        readiness["detail"] = "tcpdump not installed"
        return readiness

    probe = Path("/usr/bin/.capture_env_write_probe")
    try:
        probe.touch()
        readiness["usr_writable"] = True
        probe.unlink(missing_ok=True)
    except OSError:
        readiness["usr_writable"] = False

    try:
        result = subprocess.run(
            [tcpdump, "-i", "any", "-c", "1", "-nn"],
            capture_output=True, text=True, timeout=6, check=False,
        )
        combined = (result.stdout or "") + (result.stderr or "")
        if "permission" in combined.lower() or "CAP_NET_RAW" in combined:
            readiness["detail"] = "requires CAP_NET_RAW / root"
        elif result.returncode == 0:
            readiness["unprivileged_capture_works"] = True
            readiness["detail"] = "unprivileged capture succeeded"
        else:
            readiness["detail"] = combined.strip().splitlines()[0] if combined.strip() else "unknown"
    except subprocess.TimeoutExpired:
        # Timing out while waiting for a packet means the socket opened fine.
        readiness["unprivileged_capture_works"] = True
        readiness["detail"] = "capture socket opened (timed out waiting for a packet)"
    return readiness


def collect() -> dict:
    return {
        "tool_versions": tool_versions(),
        "interfaces": interfaces(),
        "default_route_interface": default_route_interface(),
        "dns_servers": dns_servers(),
        "capture_readiness": capture_readiness(),
    }


if __name__ == "__main__":
    print(json.dumps(collect(), indent=2))
