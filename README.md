# Halo MCC Online Preservation

Evidence-driven research and compatibility work for preserving privately operated online functionality in **Halo: The Master Chief Collection (MCC) on PC**.

## Current state

**Phase 0 only: bank, capture, inventory, and adjudicate architecture.**

No production-service impersonation, matchmaking implementation, dedicated-server claim, token forgery, or client binary patch is accepted until the corresponding evidence gate is passed.

## Primary questions

1. Which MCC service endpoints and manifests are used by the pinned retail PC build?
2. What is the exact MCC authentication chain and title-token format?
3. Which Xbox services are called directly, and which behaviors are mediated by Halo-specific services?
4. How are peers and dedicated servers allocated, paired, configured, and addressed?
5. Does the retail client contain reachable server-mode logic, or is UDS server code absent from the shipped client?
6. Can private custom games, Forge, CGB, and matchmaking be restored through documented-compatible services without reproducing Microsoft-controlled identity or trust claims?

## Non-goals

- Bypassing ownership, platform entitlements, bans, anti-cheat, or account security
- Connecting modified clients to official matchmaking
- Distributing Microsoft binaries, keys, certificates, tokens, or proprietary assets
- Reusing captured credentials or impersonating real users
- Claiming a dedicated server exists before binary and network evidence proves it

## Repository policy

This repository stores sanitized schemas, metadata, hashes, tools, documentation, and tests. Raw captures, retail binaries, depot contents, certificates, and secrets remain local and are ignored by Git.

Start with [`docs/STATUS.md`](docs/STATUS.md), [`docs/PHASE_0_BOOTSTRAP.md`](docs/PHASE_0_BOOTSTRAP.md), and [`docs/CAPTURE_MATRIX.md`](docs/CAPTURE_MATRIX.md).
