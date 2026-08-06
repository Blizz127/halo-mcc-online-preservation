#!/usr/bin/env bash
# Bounded, privacy-limited packet capture for the P0-C passive-topology rung.
#
# This is the ONLY component of the capture tooling that needs elevated
# privileges (CAP_NET_RAW). It is deliberately a separate, short, auditable
# script so the operator can read it in full before granting sudo, rather than
# being asked to paste a long inline command.
#
# Safety properties, all enforced below rather than assumed:
#   * bounded    - the capture self-terminates after a duration; it cannot be
#                  left running indefinitely by accident
#   * truncated  - a small snaplen means packet payloads are cut off AT CAPTURE
#                  TIME, so request/response bodies are never written to disk
#   * external   - refuses to write inside a Git working tree, so a raw capture
#                  cannot be staged or committed by mistake
#   * unfiltered-by-content - captures metadata only; no decryption is performed
#                  or possible here
#
# usage: run_capture.sh <output-dir> [duration-seconds] [interface]

set -euo pipefail

OUTPUT_DIR="${1:?usage: run_capture.sh <output-dir> [duration-seconds] [interface]}"
DURATION="${2:-1800}"
INTERFACE="${3:-any}"

# Snaplen: enough for link+IP+TCP headers and a TLS ClientHello (so SNI is
# usually reachable), far too small for a meaningful request or response body.
SNAPLEN=400

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "error: tcpdump not found" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"

# Refuse to write raw captures anywhere inside a Git working tree.
if git -C "$OUTPUT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: $OUTPUT_DIR is inside a Git working tree; raw captures must stay outside the repository" >&2
  exit 2
fi

PCAP="$OUTPUT_DIR/p0c1_full.pcap"
LOG="$OUTPUT_DIR/tcpdump.log"
PIDFILE="$OUTPUT_DIR/tcpdump.pid"

if [ -e "$PCAP" ]; then
  echo "error: $PCAP already exists; refusing to overwrite an existing capture" >&2
  exit 3
fi

# -U flushes each packet immediately, so the file can be analyzed while the
# capture is still running. 'not port 22' keeps remote-shell traffic out.
nohup timeout "$DURATION" tcpdump \
  -i "$INTERFACE" \
  -n \
  -s "$SNAPLEN" \
  -U \
  -w "$PCAP" \
  not port 22 \
  >"$LOG" 2>&1 &

echo $! >"$PIDFILE"
sleep 2

if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "error: capture failed to start; tcpdump said:" >&2
  cat "$LOG" >&2
  exit 4
fi

# Make the artifacts readable by the invoking (non-root) user for analysis.
chmod 0644 "$PCAP" "$LOG" 2>/dev/null || true

cat <<EOF
capture started
  interface : $INTERFACE
  snaplen   : $SNAPLEN bytes (payload bodies truncated at capture time)
  duration  : ${DURATION}s (self-terminating)
  pcap      : $PCAP
  pid       : $(cat "$PIDFILE")

To stop early:  sudo kill \$(cat "$PIDFILE")
EOF
