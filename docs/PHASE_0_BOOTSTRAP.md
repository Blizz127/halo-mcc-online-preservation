# Phase 0 bootstrap

## Repository creation

Recommended GitHub repository:

- Owner: `Blizz127`
- Name: `halo-mcc-online-preservation`
- Visibility: private
- Default branch: `main`
- Description: `Evidence-driven compatibility research for preserving private Halo MCC PC online functionality.`

After extracting this scaffold:

```bash
git init -b main
git add .
git commit -m "Initialize MCC online preservation workbench"
gh repo create Blizz127/halo-mcc-online-preservation \
  --private \
  --description "Evidence-driven compatibility research for preserving private Halo MCC PC online functionality." \
  --source . \
  --remote origin \
  --push
```

## First bounded work item: P0-A

P0-A is repository bootstrap only, exactly as scoped in `docs/ROADMAP.md` §P0-A: create the
private repository, pin scope, establish secret handling, and add evidence templates. P0-A
banks no retail, binary, or capture evidence.

1. Verify `.gitignore` excludes raw captures, binaries, depots, certificates, and tokens.
2. Confirm the evidence templates and claim format in `docs/EVIDENCE_POLICY.md` are in place.
3. Write a report; do not yet record retail build identity, install capture tooling, redirect
   service domains, or modify the client.

### Boundary: not part of P0-A

The steps below are evidence-banking work assigned to later rungs by `docs/ROADMAP.md`. They
are listed here only to mark the boundary and are **not** authorized by P0-A:

- Record the Windows capture machines without personal identifiers — **P0-B**.
- Record MCC storefront, installed title packages, launch mode, and executable hashes — **P0-B**.
- Install and version-pin Wireshark and one HTTP interception tool — **P0-C**.
- Prove a known HTTPS request is visible both in Wireshark and decrypted capture — **P0-C**.
- Test MCC with the proxy applied to WinHTTP — **P0-C**.

Each later rung requires its own explicit authorization before it begins.

## Stop conditions

Stop immediately if:

- A capture contains credentials that cannot be safely isolated.
- The test risks sending modified traffic to official services.
- A tool proposes disabling account, entitlement, or anti-cheat controls beyond the official EAC-disabled mode.
- Evidence no longer distinguishes MCC observations from Halo Infinite assumptions.
