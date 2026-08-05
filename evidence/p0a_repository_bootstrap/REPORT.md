# P0-A report: repository bootstrap

## Repository path

`/home/blizz/dev/halo-mcc-online-preservation`

## Branch

`main` (single branch, tracks `origin/main`)

## Remote

- `origin`: `https://github.com/Blizz127/halo-mcc-online-preservation.git`
- Visibility: private (confirmed via `gh repo view --json visibility`)
- The repository already existed on GitHub, created empty at `2026-08-05T22:03:08Z` with no default branch. It was reused as `origin` rather than recreated, since `gh repo create` would have failed on the existing name.

## Commit

- Hash: `a4a1b2b78e2c84b19c63a8d29724c21dcd2bce81`
- Message: `Initialize MCC online preservation workbench`
- Root commit, 25 files changed, 545 insertions
- Pushed to `origin/main` as a new branch (`git push -u origin main`)

## Scaffold Phase-0 scope review

Every scaffold document was read and checked for scope consistency. All nine constrain work to Phase 0:

| Document | Phase-0 constraint |
|---|---|
| `README.md` | "Phase 0 only"; non-goals bar impersonation, entitlement/anti-cheat bypass, binary distribution |
| `CLAUDE.md` | "Current authorized phase: **P0 only**"; bars auth forgery, matchmaking, UDS, client injection |
| `docs/STATUS.md` | Current phase P0; 8-item completion gate; "No Phase 1 shim or service implementation starts before this gate" |
| `docs/ROADMAP.md` | P0-A…P0-H precede P1+; each later phase gated on prior evidence |
| `docs/PHASE_0_BOOTSTRAP.md` | Bootstrap steps plus four hard stop conditions |
| `docs/EVIDENCE_POLICY.md` | Explicit allowed/forbidden commit lists; claim format requires evidence IDs |
| `docs/LEGAL_AND_SAFETY.md` | Private repo, no bypass, no official-matchmaking connection, no secret retention |
| `docs/ARCHITECTURE_HYPOTHESES.md` | All seven claims `Unproven`/`Partially supported`; Infinite cannot be promoted to MCC fact |
| `docs/MODEL_ROUTING.md` | Claude "must not implement beyond the current phase gate"; auditor is read-only |

Two internal inconsistencies were found and are **not** corrected here (correcting scaffold text was outside this rung's authorization):

1. **P0-A is defined twice, at different widths.** `docs/ROADMAP.md` scopes P0-A to "Create the private repository, pin scope, establish secret handling, and add evidence templates" — repository bootstrap only. `docs/PHASE_0_BOOTSTRAP.md` §"First bounded work item: P0-A" scopes it to seven steps, of which 4–6 (install/version-pin Wireshark and an HTTP interception tool, prove a known HTTPS request appears in decrypted capture, test MCC with a WinHTTP proxy) are capture-path work that `docs/ROADMAP.md` assigns to **P0-C**. Only the narrower ROADMAP definition was executed; steps 4–6 were not performed and were outside the authorization for this rung.
2. **`docs/STATUS.md` "Accepted facts" carry no evidence IDs**, though `docs/EVIDENCE_POLICY.md` §"Claim format" requires every recorded claim to cite them. The five accepted facts read as official-primary-source statements but are uncited, so they cannot currently be traced or re-adjudicated.

No scaffold document authorizes, or contains scaffolding for, capture execution, certificate/interception infrastructure, FastAPI services, authentication, matchmaking, MPSD, UDS, or client-shim code. No Halo Infinite observation is stated as an MCC fact; Infinite appears only as an explicitly-labelled analogy in `docs/STATUS.md` hypotheses and `docs/ARCHITECTURE_HYPOTHESES.md`.

## Test results

`tests/test_repository_contract.py::test_required_phase_zero_documents_exist` — **PASSED** (1/1).

No system-wide `pytest` was available (`pip3 install` refused under PEP 668 externally-managed-environment). A local `.venv/` was created and `pytest>=8.3` installed into it per the `dev` extra in `pyproject.toml`. `.venv/` is excluded by `.gitignore` and was not committed.

```
tests/test_repository_contract.py::test_required_phase_zero_documents_exist PASSED [100%]
1 passed in 0.03s
```

## Ignored-material verification

No `.gitignore` existed in the scaffold at task start; one was authored and committed. Coverage confirmed by staging and then reverting synthetic probe files (never committed) and checking `git status --short --ignored` / `git check-ignore -v`:

| Probe | Result |
|---|---|
| `captures/raw/test.pcap` | ignored |
| `sample.har` | ignored |
| `sample.saz` | ignored |
| `notes.pem` | ignored |
| `creds.key` | ignored |
| `fake_token.json` | ignored |
| `xuid_dump.txt` | ignored |
| `secrets/thing.txt` | ignored |
| `.venv/`, `__pycache__/` | ignored |

`.gitignore` also covers PCAP/PCAPNG/CAP/ETL, retail binaries (`*.exe`, `*.dll`, `*.pdb`, `*.iso`, `*.wim`, `*.msi`), Steam depot directories (`depots/`, `steamapps/`), certificates and key material (`*.crt`, `*.cer`, `*.pfx`, `*.p12`), `.env` files, and gamertag/XUID-pattern filenames. `captures/raw/*` is ignored except its tracked `.gitkeep` placeholder; `captures/sanitized/` is not ignored, matching `captures/README.md`'s policy that only reviewed, redacted excerpts go there.

Working tree is clean after probe cleanup — `git status` shows no untracked or modified files beyond the ignore rules.

### Independent re-verification

The bootstrap above was re-verified in a second, separate session before this report was accepted. The re-check used `git check-ignore -q` against 39 synthetic paths spanning every category named in the authorization — raw captures, PCAP/PCAPNG/CAP/HAR/SAZ/ETL, retail binaries, Steam depots, secrets, tokens, certificates, account exports, and local scratch. **All 39 resolved to ignored.** `git check-ignore` evaluates path patterns without creating files, so no probe files were written to disk on this pass.

The committed tree was additionally scanned for leaked material:

- `git ls-tree -r HEAD` — 26 files, all text except five zero-byte `.gitkeep` placeholders (empty blob `e69de29`).
- Secret-pattern scan (private-key headers, JWT-shaped strings, bearer tokens, API-key assignments, XUID/gamertag literals) — every hit is policy prose in `.gitignore`, `CLAUDE.md`, `captures/README.md`, `docs/CAPTURE_MATRIX.md`, or this report. **No credential, token, key, identifier, binary, depot, or game asset is present in the commit tree.**
- `git ls-remote origin` — `refs/heads/main` is `a4a1b2b`, i.e. the initial commit and nothing further.
- `gh repo view` — `"isPrivate": true`, `"visibility": "PRIVATE"`, default branch `main`.

## Files added (initial commit)

```
.gitignore
CLAUDE.md
CONTRIBUTING.md
README.md
captures/README.md
captures/raw/.gitkeep
docs/ARCHITECTURE_HYPOTHESES.md
docs/CAPTURE_MATRIX.md
docs/EVIDENCE_POLICY.md
docs/LEGAL_AND_SAFETY.md
docs/MODEL_ROUTING.md
docs/PHASE_0_BOOTSTRAP.md
docs/ROADMAP.md
docs/STATUS.md
evidence/README.md
evidence/manifests/.gitkeep
evidence/reports/.gitkeep
fixtures/README.md
fixtures/http/.gitkeep
fixtures/session-documents/.gitkeep
pyproject.toml
scripts/hash_tree.ps1
scripts/hash_tree.sh
src/mcc_preservation/__init__.py
tests/test_repository_contract.py
```

No captures, binaries, tokens, or personal identifiers were present in the scaffold or committed.

## Unresolved setup limitations

- **P0-A was executed by two concurrent agent sessions against the same working directory.** Session A (the Claude Code Cursor extension, PID 2770896) authored the scaffold at ~22:14 UTC, committed `a4a1b2b` at 22:19:18, pushed it at 22:19:34, and committed this report at 22:20:34. Session B (terminal, PID 2760315) began by observing an empty directory — it had been started before Session A wrote anything — and on re-inspection found the bootstrap already complete. Session B did not re-run `git init`, re-create the GitHub repository, or duplicate the commit; it performed the independent re-verification recorded above and appended the scope review and this disclosure. Both sessions wrote to one untracked-then-tracked tree with no locking, so the ordering above is reconstructed from `git reflog`, filesystem mtimes, and process start times rather than from a coordinated log. **Anything in this report predating 22:20:34 is Session A's own account of its work and was verified only by re-inspecting the resulting repository state, not by observing the actions as they happened.** Future rungs should run in one session at a time.
- The scaffold named as "supplied" in the task authorization was not present in the working directory when Session B first listed it; the tree contained only `.git`. The scaffold files were authored into place by Session A. No archive, tarball, or upstream source for a pre-existing scaffold was found on disk, so the committed documents should be treated as authored-for-this-repository rather than as an external artifact reproduced verbatim.
- The target GitHub repository already existed (empty, private, correct owner/name) before this task ran. It was not recreated; no repository settings (description, branch protection) were changed beyond the push itself. If the scaffold-recommended description (`Evidence-driven compatibility research for preserving private Halo MCC PC online functionality.`) is wanted on the GitHub repo, that is a separate, explicit follow-up — not performed here to avoid an unrequested mutation of shared repository metadata.
- No system Python environment had `pytest` preinstalled; a project-local `.venv` was created ad hoc. This is not committed and is not part of the tracked scaffold — future rungs should decide whether to formalize environment setup (e.g., a documented `venv`/`uv` bootstrap step) rather than relying on this session's throwaway virtualenv.
- `captures/sanitized/` has no tracked placeholder file (no `.gitkeep`), so it does not appear in `git status` or the commit tree; it exists on disk only. This matches the scaffold as extracted and was not altered.

## Next gate

Per `docs/ROADMAP.md` and `docs/STATUS.md`, the only authorized next rung is **P0-B: Retail build bank** — recording MCC storefront, app/build identifiers, Steam depot manifests where lawfully available, file hashes, installed DLC/title packages, launch modes, and tool versions, without committing any retail files. P0-B does not begin under this task; it requires separate explicit authorization.
