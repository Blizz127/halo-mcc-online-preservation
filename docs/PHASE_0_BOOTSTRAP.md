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

1. Verify `.gitignore` excludes raw captures, binaries, depots, certificates, and tokens.
2. Record the Windows capture machines without personal identifiers.
3. Record MCC storefront, installed title packages, launch mode, and executable hashes.
4. Install and version-pin Wireshark and one HTTP interception tool.
5. Prove a known HTTPS request is visible both in Wireshark and decrypted capture.
6. Test MCC with the proxy applied to WinHTTP.
7. Write a report; do not yet redirect service domains or modify the client.

## Stop conditions

Stop immediately if:

- A capture contains credentials that cannot be safely isolated.
- The test risks sending modified traffic to official services.
- A tool proposes disabling account, entitlement, or anti-cheat controls beyond the official EAC-disabled mode.
- Evidence no longer distinguishes MCC observations from Halo Infinite assumptions.
