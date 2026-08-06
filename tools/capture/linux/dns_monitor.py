"""Timestamped DNS observation via `resolvectl monitor` (unprivileged).

`resolvectl monitor` is the primary DNS source for this rung rather than pcap
DNS extraction, for two reasons specific to this host:

1. DNS is routed through a VPN resolver, so queries are not necessarily visible
   as plaintext UDP/53 on the physical interface.
2. It reports the resolver's own structured view (query name, type, status, and
   answer records), which is what the domain inventory needs.

`resolvectl monitor` emits no timestamps of its own, so the runner here stamps
each line on arrival (`stdbuf -oL` forces line buffering, since the tool
block-buffers when stdout is a pipe rather than a tty). Timestamps are therefore
observation times, accurate to the read, not resolver-internal times.

Privacy note: this observes DNS for the **whole host**, including unrelated
applications. Nothing here filters by process — that correlation happens later,
in `build_topology.py`, which keeps only names that resolve to an address a
target process was actually observed talking to. Raw monitor logs stay in local
scratch and are never committed.
"""

from __future__ import annotations

import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

_QUERY_RE = re.compile(r"^\s*(?:→|->)\s*Q:\s*(?P<name>\S+)\s+IN\s+(?P<qtype>\S+)")
_STATUS_RE = re.compile(r"^\s*(?:←|<-)\s*S:\s*(?P<status>\S+)")
_ANSWER_RE = re.compile(r"^\s*(?:←|<-)\s*A:\s*(?P<name>\S+)\s+IN\s+(?P<rtype>\S+)\s*(?P<rdata>.*)$")


@dataclass
class DnsTransaction:
    first_seen: float
    queries: list[tuple[str, str]] = field(default_factory=list)   # (name, qtype)
    status: str | None = None
    answers: list[tuple[str, str, str]] = field(default_factory=list)  # (name, rtype, rdata)

    @property
    def query_names(self) -> list[str]:
        return [name for name, _ in self.queries]

    def resolved_addresses(self) -> list[str]:
        return [rdata.strip() for name, rtype, rdata in self.answers if rtype in ("A", "AAAA") and rdata.strip()]


def run_monitor(output_path: Path, duration_seconds: float | None = None) -> int:
    """Stream timestamped `resolvectl monitor` lines into output_path.

    Returns the number of lines written. Runs until duration elapses, or until
    interrupted/EOF when duration is None.
    """
    output_path = Path(output_path)
    written = 0

    # stdbuf keeps lines flowing; without it resolvectl block-buffers into a pipe.
    cmd = ["stdbuf", "-oL", "resolvectl", "monitor"]
    with output_path.open("w", encoding="utf-8") as sink:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

        # A watchdog terminates the child at the deadline. Checking the clock
        # inside the read loop is not sufficient: iterating the pipe blocks
        # until the next line arrives, so an idle window with no DNS activity
        # would otherwise never reach the deadline check and would hang.
        watchdog = None
        if duration_seconds is not None:
            watchdog = threading.Timer(duration_seconds, proc.terminate)
            watchdog.daemon = True
            watchdog.start()

        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                sink.write(f"{time.time():.6f}\t{line.rstrip()}\n")
                sink.flush()
                written += 1
        finally:
            if watchdog is not None:
                watchdog.cancel()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    return written


def parse_monitor_log(path: Path) -> list[DnsTransaction]:
    """Parse a timestamped monitor log into DNS transactions.

    Transactions are separated by blank lines in `resolvectl monitor` output.
    A query line always starts a transaction; status/answer lines attach to the
    transaction currently open.
    """
    transactions: list[DnsTransaction] = []
    current: DnsTransaction | None = None

    for raw_line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        timestamp_str, _, line = raw_line.partition("\t")
        try:
            timestamp = float(timestamp_str)
        except ValueError:
            timestamp, line = 0.0, raw_line

        if not line.strip():
            current = None
            continue

        query = _QUERY_RE.match(line)
        if query:
            if current is None:
                current = DnsTransaction(first_seen=timestamp)
                transactions.append(current)
            current.queries.append((query.group("name").rstrip("."), query.group("qtype")))
            continue

        status = _STATUS_RE.match(line)
        if status:
            if current is None:
                current = DnsTransaction(first_seen=timestamp)
                transactions.append(current)
            current.status = status.group("status")
            continue

        answer = _ANSWER_RE.match(line)
        if answer:
            if current is None:
                current = DnsTransaction(first_seen=timestamp)
                transactions.append(current)
            current.answers.append((
                answer.group("name").rstrip("."),
                answer.group("rtype"),
                answer.group("rdata").strip(),
            ))

    return transactions


def address_to_names(transactions: list[DnsTransaction]) -> dict[str, set[str]]:
    """Map each resolved IP address to the query name(s) that produced it.

    This is the join key used to attribute a socket's peer address back to a
    hostname without ever trusting reverse DNS.
    """
    mapping: dict[str, set[str]] = {}
    for transaction in transactions:
        names = set(transaction.query_names)
        # An answer chain may rename via CNAME; keep answer-side owner names too.
        names.update(name for name, rtype, _ in transaction.answers if rtype in ("A", "AAAA"))
        for address in transaction.resolved_addresses():
            mapping.setdefault(address, set()).update(names)
    return mapping


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    run = sub.add_parser("run", help="record timestamped resolvectl monitor output")
    run.add_argument("output", type=Path)
    run.add_argument("--seconds", type=float, default=None)

    show = sub.add_parser("parse", help="summarize a recorded monitor log")
    show.add_argument("log", type=Path)

    args = parser.parse_args()

    if args.mode == "run":
        lines = run_monitor(args.output, args.seconds)
        print(f"wrote {lines} lines to {args.output}", file=sys.stderr)
    else:
        parsed = parse_monitor_log(args.log)
        print(json.dumps({
            "transactions": len(parsed),
            "distinct_names": sorted({n for t in parsed for n in t.query_names}),
            "addresses": {k: sorted(v) for k, v in sorted(address_to_names(parsed).items())},
        }, indent=2))
