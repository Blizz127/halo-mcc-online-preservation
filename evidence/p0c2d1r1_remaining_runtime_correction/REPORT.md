# P0-C2D1-R1 remaining-runtime and retry-contract correction

Outcome: **tooling/runbook correction complete under synthetic validation only**. No Steam/MCC
process was started, no certificate was generated, no trust or redirect was installed, no observer
or proxy was started, and no production service was contacted.

## Historical record preserved

Commit `ed9e3230bf559e01b7c2a0ba9938326da667c173` remains unchanged as the historical partial live
P0-C2D1 attempt. Its outcome is `E. SNI / OBSERVER CONTRACT FAILURE`: the observer expired before
live client contact, its 240.103-second result contained zero observations, and Steam launch was
issued after expiry. No SNI, TLS, ALPN, application-data, certificate-acceptance, or pinning result
was obtained. Prefix-only trust, exact-host redirect, processes, and scratch were fully removed or
restored afterward.

R1 does not reinterpret that event as a halted-at-gate attempt.

## Remaining-runtime contract

`tls_observer.py` now publishes the same owned runtime fields in its PID and ready controls:

- process and run identifiers;
- boot-monotonic run start and deadline;
- configured timeout;
- wall-clock audit timestamp; and
- exact ready bind/port ownership.

The read-only `--check-launch-window` mode cross-checks both controls, rejects replacement during
inspection, verifies the observer process, verifies that the process owns the exact
`127.0.0.77:443` listener through `/proc`, computes elapsed and remaining time from monotonic state,
and emits sanitized JSON. It exits nonzero unless every check passes.

The minimum is `MIN_LIVE_LAUNCH_REMAINING_SECONDS = 150`. This is twice the measured 75-second
redirect-verify-to-connect interval: one measured arrival interval plus another 75 seconds of
operational margin. It is also above the approximately 72-second launch-to-title-service evidence
and is compatible with the recommended 240-second observer runtime.

Missing, malformed, mismatched, unstable, expired, negative, insufficient, or internally
inconsistent state fails closed. If the gate fails, Steam/MCC must not launch; any redirect and
prefix trust must be rolled back, and the result is a pre-launch safety abort rather than
`D. OBSERVER NOT CONTACTED`.

## Direct-baseline contract

The `p0c2d1r1-direct-baseline-v1` input records booleans for normal Steam launch, normal MCC launch,
Microsoft/Xbox identity success, main-menu success, certificate/service error, and clean shutdown,
plus `sign_in_mode` as `cached`, `interactive`, or `unknown`. The read-only `--check-baseline` mode
emits a sanitized decision and exits nonzero for missing/wrongly typed fields or any failed required
assertion. Vague prose is not accepted as a baseline.

## Corrected retry sequence

Any separately authorized live retry must gate the repository/environment; record and accept the
direct baseline; fully exit Steam/MCC; create fresh scratch and fresh exact-host material; run final
preflight; install prefix trust; start and verify the observer; install and verify the exact redirect
and protected scope; run the remaining-runtime gate; launch Steam/MCC immediately only on
`safe_to_launch: true`; observe; and roll back as soon as a sufficient result exists.

No live retry was begun by R1. P0-C2D1 remains incomplete, no TLS trust verdict exists, and P0-C2E
remains unstarted.

## Evidence inventory

- `contract_example.json`: sanitized example of the machine-readable gate output.
- `validation.txt`: exact synthetic validation and final read-only safety checks.
- `tool_versions.txt`: hashes of the corrected tool, test, and runbook inputs.
