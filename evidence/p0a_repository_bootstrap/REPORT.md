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

- The target GitHub repository already existed (empty, private, correct owner/name) before this task ran. It was not recreated; no repository settings (description, branch protection) were changed beyond the push itself. If the scaffold-recommended description (`Evidence-driven compatibility research for preserving private Halo MCC PC online functionality.`) is wanted on the GitHub repo, that is a separate, explicit follow-up — not performed here to avoid an unrequested mutation of shared repository metadata.
- No system Python environment had `pytest` preinstalled; a project-local `.venv` was created ad hoc. This is not committed and is not part of the tracked scaffold — future rungs should decide whether to formalize environment setup (e.g., a documented `venv`/`uv` bootstrap step) rather than relying on this session's throwaway virtualenv.
- `captures/sanitized/` has no tracked placeholder file (no `.gitkeep`), so it does not appear in `git status` or the commit tree; it exists on disk only. This matches the scaffold as extracted and was not altered.

## Next gate

Per `docs/ROADMAP.md` and `docs/STATUS.md`, the only authorized next rung is **P0-B: Retail build bank** — recording MCC storefront, app/build identifiers, Steam depot manifests where lawfully available, file hashes, installed DLC/title packages, launch modes, and tool versions, without committing any retail files. P0-B does not begin under this task; it requires separate explicit authorization.
