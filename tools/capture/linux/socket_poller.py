"""Socket -> process correlation by repeated unprivileged `ss` sampling.

`ss -tunpH` reports process ownership for the invoking user's own sockets
without elevation, which is what makes process attribution possible for this
rung. Sampling is inherently lossy: a connection opened and closed entirely
between two samples is never seen. That limitation is recorded rather than
hidden — `Flow.sample_count` shows how many samples observed each flow, and a
flow seen exactly once is weak timing evidence.

Read-only: this module only runs `ss` and parses its output. It never opens,
closes, or modifies a socket.
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

_PROC_RE = re.compile(r'\("(?P<name>[^"]+)",pid=(?P<pid>\d+),fd=(?P<fd>\d+)\)')


@dataclass(frozen=True)
class Endpoint:
    address: str
    port: int

    def __str__(self) -> str:
        return f"{self.address}:{self.port}"


@dataclass
class Flow:
    netid: str
    state: str
    local: Endpoint
    peer: Endpoint
    processes: set[tuple[str, int]] = field(default_factory=set)  # (comm, pid)
    first_seen: float = 0.0
    last_seen: float = 0.0
    sample_count: int = 0


def _split_host_port(token: str) -> Endpoint | None:
    """Split an `ss` address token into address and port.

    Handles IPv4 (`192.0.2.10:443`), bracketed IPv6 (`[2001:db8::1]:443`),
    scoped addresses (`192.0.2.10%wlan0:68`), and wildcard forms (`*:443`).
    Examples use the RFC 5737 / RFC 3849 documentation ranges so no real
    address from a capture appears in source.
    """
    token = token.strip()
    if not token or ":" not in token:
        return None
    address, _, port_str = token.rpartition(":")
    if not port_str:
        return None
    address = address.split("%", 1)[0]
    if address.startswith("[") and address.endswith("]"):
        address = address[1:-1]
    try:
        port = int(port_str)
    except ValueError:
        return None  # e.g. a named port or "*"
    return Endpoint(address=address, port=port)


def parse_ss_line(line: str) -> tuple[str, str, Endpoint, Endpoint, set[tuple[str, int]]] | None:
    """Parse one `ss -tunpH` row. Returns None for rows without a usable 5-tuple."""
    if not line.strip():
        return None
    # Split the process column off first: it is the only field that can contain spaces.
    body, _, process_blob = line.partition("users:(")
    fields = body.split()
    if len(fields) < 6:
        return None
    netid, state = fields[0], fields[1]
    local = _split_host_port(fields[4])
    peer = _split_host_port(fields[5])
    if local is None or peer is None:
        return None

    processes = {
        (m.group("name"), int(m.group("pid")))
        for m in _PROC_RE.finditer("(" + process_blob if process_blob else "")
    }
    return netid, state, local, peer, processes


def sample_once(timestamp: float | None = None) -> list[tuple[str, str, Endpoint, Endpoint, set[tuple[str, int]]]]:
    result = subprocess.run(
        ["ss", "-tunpH"], capture_output=True, text=True, timeout=15, check=False
    )
    rows = []
    for line in result.stdout.splitlines():
        parsed = parse_ss_line(line)
        if parsed is not None:
            rows.append(parsed)
    return rows


def poll(
    duration_seconds: float,
    interval_seconds: float = 0.5,
    output_path: Path | None = None,
    checkpoint_seconds: float = 15.0,
) -> dict[tuple, Flow]:
    """Sample sockets repeatedly and aggregate into flows keyed by 5-tuple.

    Results are checkpointed to `output_path` periodically, not only at the end.
    A long capture that is interrupted — or simply inspected while still
    running — would otherwise yield nothing at all, since the aggregate lives
    only in memory until the run completes.
    """
    flows: dict[tuple, Flow] = {}
    deadline = time.time() + duration_seconds
    next_checkpoint = time.time() + checkpoint_seconds

    while time.time() < deadline:
        now = time.time()
        for netid, state, local, peer, processes in sample_once():
            key = (netid, str(local), str(peer))
            flow = flows.get(key)
            if flow is None:
                flow = Flow(
                    netid=netid, state=state, local=local, peer=peer,
                    first_seen=now, last_seen=now, sample_count=0,
                )
                flows[key] = flow
            flow.last_seen = now
            flow.sample_count += 1
            flow.state = state
            flow.processes.update(processes)

        if output_path is not None and time.time() >= next_checkpoint:
            write_flows_jsonl(flows, output_path)
            next_checkpoint = time.time() + checkpoint_seconds

        time.sleep(max(0.0, interval_seconds - (time.time() - now)))

    if output_path is not None:
        write_flows_jsonl(flows, output_path)
    return flows


def write_flows_jsonl(flows: dict[tuple, Flow], path: Path) -> None:
    import json

    with Path(path).open("w", encoding="utf-8") as sink:
        for flow in flows.values():
            sink.write(json.dumps({
                "netid": flow.netid,
                "state": flow.state,
                "local_address": flow.local.address,
                "local_port": flow.local.port,
                "peer_address": flow.peer.address,
                "peer_port": flow.peer.port,
                "processes": sorted([list(p) for p in flow.processes]),
                "first_seen": flow.first_seen,
                "last_seen": flow.last_seen,
                "sample_count": flow.sample_count,
            }) + "\n")


def read_flows_jsonl(path: Path) -> list[dict]:
    import json

    records = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--seconds", type=float, required=True)
    parser.add_argument("--interval", type=float, default=0.5)
    args = parser.parse_args()

    collected = poll(args.seconds, args.interval, args.output)
    print(f"observed {len(collected)} distinct flows -> {args.output}")
