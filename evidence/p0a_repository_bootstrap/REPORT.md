# P0-A report: repository bootstrap

## Repository path

`<REPOSITORY_ROOT>`

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

---

# Addendum: post-bootstrap audit and remediation

**Added after the fact.** Everything above this line is the original P0-A report as committed
in `051aa86` and `280731b`, and is unchanged. This section is a later audit record appended in
a separate session; it does not revise, retract, or conceal the report history above.

## Audit finding

An independent read-only audit was run against the repository after P0-A was reported
complete. It accepted the bootstrap itself — ignore coverage, clean commit tree, private
remote, and the single passing contract test all re-verified — and confirmed the two scope
inconsistencies that the original report had recorded but, by its own authorization, left
uncorrected. Those two defects were the audit's substantive findings, and they are the entire
scope of the remediation below.

At audit time both report commits were **already present on the remote**:
`git ls-remote origin refs/heads/main` resolved to `280731b`, with `051aa86` as its parent.
Neither could be edited in place, so remediation had to be forward-only by construction as
well as by instruction.

### Finding 1 — P0-A definition conflict

`docs/ROADMAP.md` §P0-A scoped the rung to repository bootstrap: create the private
repository, pin scope, establish secret handling, add evidence templates.
`docs/PHASE_0_BOOTSTRAP.md` §"First bounded work item: P0-A" scoped it to seven steps, five of
which are evidence-banking work that `docs/ROADMAP.md` assigns elsewhere — recording capture
machines and MCC build identity (**P0-B**), and installing capture tooling, proving decrypted
HTTPS visibility, and testing MCC behind a WinHTTP proxy (**P0-C**). A reader following the
bootstrap document alone would have treated capture-path work as already authorized. Only the
narrower ROADMAP definition was ever executed.

### Finding 2 — uncited accepted facts

`docs/STATUS.md` §"Accepted facts" listed five claims about MCC's online architecture and
launch modes. `docs/EVIDENCE_POLICY.md` §"Claim format" requires every recorded claim to cite
evidence IDs. None of the five did, and a repository-wide search found **no evidence IDs
defined anywhere** — expected, since P0-A banks no retail, binary, or capture evidence. The
five were therefore untraceable and un-adjudicable while carrying the authority of fact.

## Remediation

Three forward-only commits on `main`. No existing commit was rewritten, reset, rebased,
amended, squashed, or reverted; no force-push was performed; nothing was pushed at all.

| Rung | Commit | Message | Files changed |
|---|---|---|---|
| R1 | `27ecccd3cf90e99b1a2f71eefc79308d0daeef05` | `Clarify P0-A bootstrap boundary` | `docs/PHASE_0_BOOTSTRAP.md` |
| R2 | `062c3d2b0f4b9f0d85da186c3c4ad519e927839a` | `Align MCC claims with evidence policy` | `docs/ARCHITECTURE_HYPOTHESES.md`, `docs/STATUS.md` |
| R3 | this commit | `Document P0-A remediation audit` | `evidence/p0a_repository_bootstrap/REPORT.md` |

**R1** restated §"First bounded work item: P0-A" as repository bootstrap only, matching
`docs/ROADMAP.md`, and moved the five later-rung steps into a "Boundary: not part of P0-A"
list that names the owning rung (P0-B or P0-C) and marks each as unauthorized. P0-A was not
broadened; no later rung was authorized.

**R2** emptied §"Accepted facts" and stated plainly that no claim currently satisfies the
evidence policy, rather than manufacturing evidence IDs to retain the five entries. They were
relocated to `docs/ARCHITECTURE_HYPOTHESES.md` as **H-008 – H-012**, each `Unproven` with its
required evidence and consequence recorded, plus a provenance note preserving their apparent
source context — public statements on MCC online architecture (H-008 – H-011) and official MCC
support documentation for the EAC-disabled launch mode (H-012) — explicitly as investigation
leads, not as evidence. A scope statement was added to both documents keeping Halo Infinite
outside project scope, admissible only as independent secondary source that must be
independently confirmed against MCC evidence before it can change any claim's state.

## Test and validation results

Run with the existing project-local `.venv` (`.venv/bin/python -m pytest -q`), which remains
untracked and ignored:

```
tests/test_repository_contract.py::test_required_phase_zero_documents_exist PASSED [100%]
1 passed
```

That is the full repository suite — one test, the Phase-0 document contract, which still
passes because R1 and R2 edited required documents in place and removed none.

| Check | Result |
|---|---|
| Full test suite | 1 passed, 0 failed |
| `git diff --check` | clean, exit 0 |
| Markdown well-formed | verified — headings, fences, and table column counts consistent in all three edited files |
| Working tree | clean; no untracked or modified files |
| History shape | `a4a1b2b` ← `051aa86` ← `280731b` ← R1 ← R2 ← R3, linear, no rewrite |
| Added material | documentation text only — no captures, binaries, tokens, secrets, certificates, game assets, or retail files |

## Local and remote relationship

Local `main` is three commits ahead of `origin/main`. `origin/main` remains at `280731b` and
was not modified: nothing was pushed under this task. The three remediation commits exist
locally only, and pushing them is a separate decision.

## Authorization status

**P0-B remains unauthorized.** This task covered audit remediation only. The next rung is
still P0-B: Retail build bank, and it requires its own explicit authorization before any work
on it begins. Nothing in R1–R3 authorizes retail inspection, capture execution, tooling
installation, or service implementation.

---

# P0-A corrective closeout

Added after R1–R3, in a single session with no other agent process running (the concurrent
session, PID 2770896, was confirmed exited before any write in this closeout). This section
is the last entry for P0-A.

## Concurrent-write integrity audit

The commit chain was audited for damage from the two-session overlap documented above.

| Check | Method | Result |
|---|---|---|
| Object-store integrity | `git fsck --full --strict` | No corruption, no missing objects |
| Blob fidelity | Re-hashed every blob in all six commits via `git cat-file` → `git hash-object` | 25/26/26/26/26/26 blobs, **0 mismatches** |
| Merge/conflict artifacts | `git grep` for conflict markers across `HEAD` | None |
| Interleaved writes | Duplicate-heading count on the four files both sessions touched | 15/5/3/3 headings, all unique — no duplication |
| Truncation | NUL-byte scan, zero-length scan, trailing-newline check | None truncated; only the five intentional `.gitkeep` files are empty |
| History rewrites | `git reflog` reviewed end to end | None — every commit is forward-only, no amend/rebase/reset landed |

**One dangling object was found and is explained:** commit `f96b64b` ("WIP on main"), dated
23:09:28. It is a `git stash` object created and orphaned by the auditing session's own
`stash push`/`stash pop` during verification, not a lost commit from either working session.
Its tree differs from `main` only by the uncommitted `.gitignore` edit that this closeout
supersedes. It is unreachable and will be reaped by `git gc`; no content is stranded in it.

**Verdict: the commit chain is clean.** No concurrent-write damage reached any commit. The
overlap produced redundant *process* — two agents duplicating analysis — but no corrupted,
truncated, interleaved, or lost repository content.

## Defect corrected in this commit

An uncommitted `.gitignore` modification was left in the working tree at 23:05:10 by the
session that has since exited. It broadened `*token*.json` → `*token*` (stricter, retained)
but added un-ignore rules `!*token*.md`, `!*tokens*.md`, and `!account_export*.md`.

Verified effect before correction: `title_token_capture.md`, `spartan_token.md`,
`xsts_tokens.md`, `token_notes.md`, and `account_export_dump.md` were all committable.

This was **not a regression** — `HEAD` did not ignore those paths either, since it only
covered `*token*.json`. The defect is that it codified the gap as a deliberate whitelist. A
captured token pasted into a note is the most likely leak path in this project, and Markdown
is the format notes are written in, so an explicit carve-out for exactly that combination
inverts the intended protection.

Correction: the broadening was kept, the three un-ignore rules were dropped, and the rule now
matches the blanket style already used for `*xuid*` and `*gamertag*`. `git add -f` remains as
a deliberate, visible escape hatch for any file that must legitimately carry the pattern.

Post-correction verification:

- All nine previously-committable token/account paths — **ignored**.
- Full 39-path probe set spanning every category in the authorization — **39 probes, 0 failures**.
- `git ls-files | git check-ignore --stdin` — **empty**, so no tracked file is shadowed by the
  stricter rules.

## Closeout state

- Bullet 1, P0-A phase-definition conflict — resolved in `27ecccd`, verified here.
- Bullet 2, evidence IDs for the five accepted facts — resolved in `062c3d2`, verified here:
  `H-008`–`H-012` exist with populated required-evidence columns, `docs/STATUS.md`
  §"Accepted facts" reads **None**, and no reference dangles. No evidence ID was fabricated.
- Bullet 3, concurrent-write check — performed above; chain clean.
- Bullet 4, one corrective commit — this commit.
- Bullet 5 — nothing pushed; `origin/main` stays at `280731b`. P0-B not started.

`tests/test_repository_contract.py` passes (1/1) after this change.
