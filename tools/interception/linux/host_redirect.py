"""Exact-host, reversible redirect of ONE hostname via /etc/hosts.

This is the narrowest name-based redirect available: `/etc/hosts` is consulted
before DNS (`nsswitch.conf: hosts: files ... dns`), so a single line overrides
resolution for exactly one name and nothing else. It cannot express a wildcard
or a domain suffix — a hosts entry is one literal name — which is precisely why
it is preferred here.

This module never edits `/etc/hosts` itself. Editing it needs privilege, and
this project never takes the operator's sudo password. Instead it:

  * validates that the requested redirect is exactly one permitted host,
  * emits the exact privileged install and rollback commands for the operator
    to run and read first, and
  * verifies the resulting state by reading `/etc/hosts` and by resolving names.

Two safety properties are enforced before any command is even printed:

  * the target host must equal the single selected host verbatim — a sibling,
    parent, suffix, or wildcard form is rejected, and
  * the host must not be on the P0-C2A/B exclusion denylist, so an identity or
    Xbox-auth name can never be redirected through this tool.

Inode preservation: pressure-vessel bind-mounts the host `/etc/hosts` into the
Proton container, so an in-place append (`tee -a`) propagates to an
already-running MCC, whereas a replace (`sed -i`, `mv`) would create a new inode
the container never sees. The generated commands are written to preserve the
inode for exactly this reason, and the rollback truncates-in-place rather than
renaming.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exclusions import is_excluded  # noqa: E402

HOSTS_PATH = "/etc/hosts"
SENTINEL = "# P0C2C-REDIRECT (temporary; remove at rollback)"
# A dedicated loopback address used by nothing else, so "traffic to this address
# is our observer" needs no further argument.
OBSERVER_LOOPBACK = "127.0.0.77"

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,63}$")


class RedirectSafetyError(ValueError):
    pass


def validate_target(selected_host: str, requested_host: str) -> None:
    """Reject anything but the one selected host, verbatim. Fail closed."""
    req = (requested_host or "").strip().lower().rstrip(".")
    sel = (selected_host or "").strip().lower().rstrip(".")

    if not req:
        raise RedirectSafetyError("empty host")
    if "*" in req or req.startswith("."):
        raise RedirectSafetyError(f"wildcard or suffix redirect refused: {requested_host!r}")
    if not _HOSTNAME_RE.match(req):
        raise RedirectSafetyError(f"not a valid single hostname: {requested_host!r}")
    if is_excluded(req):
        raise RedirectSafetyError(f"host is on the exclusion denylist and may never be redirected: {req}")
    if req != sel:
        raise RedirectSafetyError(
            f"requested host {req!r} is not the single selected host {sel!r}; "
            "a sibling/parent/suffix is not permitted"
        )


def install_commands(selected_host: str, address: str = OBSERVER_LOOPBACK) -> list[str]:
    """Privileged commands the OPERATOR runs to install the redirect (inode-preserving).

    Fields are space-separated, which /etc/hosts accepts, so `printf '%s'`
    reproduces the line verbatim (a literal `\\t` would not expand and would
    corrupt the entry). `tee -a` appends to the existing inode so a bind-mounted
    container sees the change.
    """
    validate_target(selected_host, selected_host)
    line = f"{address} {selected_host} {SENTINEL}"
    return [f"printf '%s\\n' {line!r} | sudo tee -a {HOSTS_PATH} >/dev/null"]


def rollback_commands() -> list[str]:
    """Privileged command to remove the redirect, preserving the /etc/hosts inode.

    `grep -v` filters our sentinel lines to a user-owned temp; `cp` back into
    the existing /etc/hosts truncates it in place (inode preserved) rather than
    renaming, which a bind mount would not follow.
    """
    tmp = "/tmp/p0c2c_hosts.clean"
    return [
        f"grep -v {SENTINEL!r} {HOSTS_PATH} > {tmp} && "
        f"sudo cp {tmp} {HOSTS_PATH} && rm -f {tmp}",
    ]


def read_our_entries() -> list[str]:
    """Lines in /etc/hosts that this tool added (identified by the sentinel)."""
    try:
        text = Path(HOSTS_PATH).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [ln for ln in text.splitlines() if SENTINEL in ln]


def is_installed(selected_host: str) -> bool:
    return any(selected_host in ln for ln in read_our_entries())


def resolve(host: str) -> list[str]:
    """Current resolution of a host (respects /etc/hosts), IPv4 only for clarity."""
    try:
        result = subprocess.run(
            ["getent", "ahostsv4", host], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return sorted({ln.split()[0] for ln in result.stdout.splitlines() if ln.split()})


def flush_dns_cache_command() -> str:
    """Unprivileged systemd-resolved cache flush (verified available at gate time)."""
    return "resolvectl flush-caches"


def verify_scope(selected_host: str, address: str, identity_hosts: list[str]) -> dict:
    """Confirm exactly the selected host points at the observer and identity hosts do not."""
    selected_ips = resolve(selected_host)
    report = {
        "selected_host": selected_host,
        "selected_resolves_to": selected_ips,
        "selected_points_at_observer": selected_ips == [address],
        "sentinel_lines_present": read_our_entries(),
        "identity_hosts": {},
        "identity_hosts_unaffected": True,
    }
    for host in identity_hosts:
        ips = resolve(host)
        redirected = address in ips
        report["identity_hosts"][host] = {"resolves_to": ips, "redirected_to_observer": redirected}
        if redirected:
            report["identity_hosts_unaffected"] = False
    return report


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("install-commands")
    pi.add_argument("selected_host")
    pi.add_argument("--address", default=OBSERVER_LOOPBACK)

    sub.add_parser("rollback-commands")

    pv = sub.add_parser("verify")
    pv.add_argument("selected_host")
    pv.add_argument("--address", default=OBSERVER_LOOPBACK)
    pv.add_argument("--identity-host", action="append", default=[
        "login.live.com", "xsts.auth.xboxlive.com", "user.auth.xboxlive.com",
    ])

    args = parser.parse_args()
    if args.cmd == "install-commands":
        print(json.dumps({"commands": install_commands(args.selected_host, args.address)}, indent=2))
    elif args.cmd == "rollback-commands":
        print(json.dumps({"commands": rollback_commands()}, indent=2))
    else:
        print(json.dumps(verify_scope(args.selected_host, args.address, args.identity_host), indent=2))
