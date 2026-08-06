# P0-B1A report: Bazzite interactive launch validation

Scope: launch modes and process behavior actually observed on the Bazzite laptop for the same
retail install already banked in `evidence/p0b1_bazzite_proton_build_bank/` (Steam appid
`976730`, buildid `19905945`). This rung is interactive by necessity — it required a human
operator to drive the Steam GUI and MCC's own UI, since neither can be scripted — but stayed
strictly read-only against processes and files: no proxy, no DNS/hosts change, no certificate
install, no packet/HAR/SAZ capture, no authentication-cache inspection, no client patch, no DLL
injection, no prefix modification, and no authentication bypass. P0-B2 and P0-C were not started.

Starting state was verified before any interactive step: branch `main`, local `main` equal to
`origin/main` at the accepted tip `3d4cded7f2c52944c529cac671cabfe6e3c99b21`, clean working tree,
and no other session touching the repository (checked via `ps` for a second `git`/agent process
and the absence of `.git/index.lock`).

## Claim 1 — Steam Properties observations

**Claim:** For appid `976730`: the General tab's Launch Options field is empty; the
Compatibility tab's "force a specific compatibility tool" override is unchecked (no per-title
tool forced); the Betas tab lists only the default (no opt-in) choice, no other branch; and
pressing Play launches the title directly with no intermediate choice menu or dropdown.

**Evidence IDs:** `E-P0B1A-001` (`launch_observations.json` → `.steam_properties`)

**Reproduction steps:** Steam Library → right-click "Halo: The Master Chief Collection" →
Properties → read General, Compatibility, and Betas tabs in turn; close Properties; press Play
and observe whether a selection menu appears before launch.

**Counter-evidence:** None. Every value here is consistent with, and independently confirms,
the noninteractive findings already banked in `evidence/p0b1_bazzite_proton_build_bank/REPORT.md`
Claims 2 and 5 (empty `CompatToolMapping`, no `LaunchOptions` key) — this rung adds direct GUI
confirmation of state that P0-B1 could only infer from config files on disk.

**Confidence:** High — direct operator observation of the Steam UI, cross-checked against
independent file-based evidence from a separate rung.

**Authorized next action:** None beyond banking.

## Claim 2 — No EAC-disabled or mod-capable launch choice is offered

**Claim:** Steam's current launch interface for this title offers no explicitly labeled
EAC-disabled, anti-cheat-disabled, or mod-capable launch choice. Per this rung's explicit
authorization, this is recorded as the literal required string rather than any inferred
mechanism:

> Not observed in the current Steam launch interface.

This rests on four independent observations, each of which would be a plausible place for such
a choice to appear and none of which showed one: an empty Launch Options field, an unforced
Compatibility tool, a Betas tab with no extra branch, and a Play button with no selection menu.

**Evidence IDs:** `E-P0B1A-002` (`launch_observations.json` → `.eac_disabled_or_mod_capable_launch`)

**Reproduction steps:** Same as Claim 1; no additional action, since finding "no choice offered"
does not require launching anything a second time.

**Counter-evidence / scope note:** This is a **gap**, not a rejection, in
`docs/ARCHITECTURE_HYPOTHESES.md` H-012 ("MCC officially supports launching on PC with Easy
Anti-Cheat disabled"). H-012 is about official support existing *somewhere* — public
documentation, a different Steam depot/branch state, a different region, or a mechanism outside
Steam's own UI entirely. This rung only establishes that the mechanism is not exposed through
*this* title's *current* Steam Properties/Play interface, on this build, in this configuration.
No command-line argument was guessed or manufactured to manufacture such a mode, per this rung's
explicit hard boundary. H-012 therefore remains `Unproven`, now with one more checked-and-absent
location on record.

**Confidence:** High for "not offered through this interface, right now." Not applicable to
H-012's broader claim, which this rung neither proves nor disproves.

**Authorized next action:** None under P0-B1A. A future rung could check official MCC support
documentation directly (an official-primary-source lookup, not a local observation) if H-012 is
ever pursued further.

## Claim 3 — Default-launch process topology

**Claim:** The default launch produces the process chain:
`steam` (Steam client, PID 4306) → `reaper "SteamLaunch AppId=976730"` →
`SteamLinuxRuntime_4/_v2-entry-point --verb=waitforexitandrun` → pressure-vessel sandbox layers →
`"Proton - Experimental"/proton waitforexitandrun mcclauncher.exe` → (`wineserver`,
two `winedevice.exe`, two `xalia.exe` Proton-accessibility helpers, and) `MCC-Win64-Shipping.exe`
as the actual retail game process — with `gameoverlayui` spawned as a sibling of the reaper tree,
directly under the Steam client process, not under the game's own subtree. A one-time
prerequisite step (Steamworks' standard `vc_redist.x86.exe /q /norestart`, driven by
`installscript.vdf`) ran once before the game process started, on this first launch of the
session.

**Evidence IDs:** `E-P0B1A-003` (`evidence/p0b1a_interactive_launch/process_topology.txt` §1–2)

**Reproduction steps:** `ps -ef --forest`, filtered to lines matching
`reaper|SteamLaunch|pressure-vessel|proton |mcclauncher|steam\.exe|wineserver|winedevice|MCC-Win64-Shipping|gameoverlay|iscriptevaluator|SteamService|vc_redist|xalia`, taken while Play was
pressed and again once the main menu was reached (topology was identical at both points, modulo
the prerequisite step only appearing before the game process existed). Sanitized with
`tools/inventory/linux/redact_process_evidence.py`.

**Counter-evidence:** None. The resolved Proton tool (`Proton - Experimental`) and prefix
(`<MCC_PROTON_PREFIX>`) match `evidence/p0b1_bazzite_proton_build_bank/REPORT.md` Claims 2–3
exactly, which is expected — this rung observed a live run of the same configuration P0-B1
inspected statically, not a different one.

**Confidence:** High — direct `ps` output, not inferred.

**Authorized next action:** None under P0-B1A. Compare against a P0-B2 native-Windows process
topology once that rung is authorized, to see which of this tree is Proton/Linux-runtime
scaffolding versus behavior the retail Windows build would show on its own.

## Claim 4 — No EAC process or module observed at default launch

**Claim:** At three checkpoints — immediately before the game process existed (during the
prerequisite step), immediately after `MCC-Win64-Shipping.exe` started, and after the main menu
was reached — no process and no module loaded into `MCC-Win64-Shipping.exe`'s address space
matched `eac`, `anticheat`, or `easyanticheat` (case-insensitive). This is despite
`easyanticheat/settings.json` (banked as `E-P0B1-007` in P0-B1, `hide_gui: "true"`,
`hide_bootstrapper: "false"`) shipping in the install tree and explicitly naming
`MCC\Binaries\Win64\MCC-Win64-Shipping.exe` as its target executable.

**Evidence IDs:** `E-P0B1A-004` (`launch_observations.json` →
`.default_launch.eac_process_observed` / `.eac_module_observed`; full 166-name module list in
`process_topology.txt` §3)

**Reproduction steps:**
1. `ps -ef | grep -iE 'eac|anticheat'` at each checkpoint.
2. `tr ' ' '\n' < /proc/<mcc_pid>/maps | grep -oE '[^/]+\.(exe|dll|so)$' | sort -u`, then search
   the result for the same pattern. This reads only the list of file paths mapped into the
   process's address space (standard OS bookkeeping any user can read for their own process via
   `/proc`), never memory contents — no attach, no ptrace, no injection.

**Counter-evidence / limits — do not over-read this finding:** This is a **static, point-in-time
absence**, not proof EAC never runs for this title:
- No online match, matchmaking flow, or other network-gated feature was entered — the operator
  only reached the main menu and Halo: Reach's mode-select screen (Claim 5). EAC could plausibly
  load lazily, later, only when a network-gated code path is reached; that path was not exercised
  and exercising it (matchmaking) is explicitly out of this rung's authorization.
- `docs/ARCHITECTURE_HYPOTHESES.md` records "absence of strings is not proof of absence" as a
  standing rule; the same caution applies here to absence of a running process/loaded module.
- This finding does not resolve H-012; it is offered as a distinct, narrower, directly-observed
  fact (no EAC process/module at menu, under the *normal* launch) that a future rung investigating
  H-012 or online-mode behavior should be aware of.

**Confidence:** High for the narrow claim ("not present at these three checkpoints, under this
launch"). Explicitly not extended to any claim about EAC's behavior during actual online play.

**Authorized next action:** A future rung reaching an online-gated menu or match (itself requiring
separate authorization, and still bounded by the no-matchmaking-service-connection rule in
`docs/LEGAL_AND_SAFETY.md`) could re-check for EAC process/module appearance at that point.

## Claim 5 — User-visible behavior at default launch

**Claim:** A Microsoft/Xbox sign-in prompt appeared and required interactive input (not
automatic/cached); after the operator signed in with their own account, the MCC main menu was
reached with no warning or error banner. Halo: Reach's own mode-select menu was reachable and
appeared normal. The other four titles (Halo 1–4/ODST, per `evidence/p0b1_bazzite_proton_build_
bank`'s finding that only the Reach depot is installed) appeared as menu tiles but showed a
not-installed/download prompt when selected, rather than launching content — consistent with,
not contradicting, that file-inventory finding. Online status displayed as connected, with no
offline indicator. On Quit, the game did not close immediately (it appeared to hang to the
operator), but a process-tree check found the entire launch chain — `MCC-Win64-Shipping.exe`,
`wineserver`, `winedevice.exe` ×2, the reaper/launcher chain — had in fact fully exited by the
time it was checked; only a defunct `gameoverlayui` helper remained, which is routine Steam
overlay cleanup, not a stuck game process. The operator independently confirmed the window was
gone. No force-kill was needed or used.

**Evidence IDs:** `E-P0B1A-005` (`launch_observations.json` → `.default_launch`, fields
`microsoft_xbox_sign_in`, `main_menu_reached`, `halo_reach_menu`, `other_titles_menu_state`,
`online_status_indicator`, `shutdown_behavior`)

**Reproduction steps:** Operator-reported observation at each stage, cross-checked against a
`ps` snapshot immediately after the reported shutdown. No account identifier, email, gamertag,
XUID, token, cookie, or authentication-cache content was requested, viewed, or recorded at any
point in this process — sign-in was confirmed only as an event (appeared / interactive /
succeeded), never by inspecting its content.

**Counter-evidence:** None found; the shutdown-delay observation is recorded exactly as it
occurred (perceived hang, confirmed-clean actual exit) rather than rounded to either "clean" or
"hung," since neither alone would be accurate.

**Confidence:** High for everything reported — either direct operator observation of the game
UI, or a `ps` check performed within roughly a minute of the reported event. Not independently
re-verified by a second run (this rung performed one default launch, not a repeated-trials
study); a single observation is what "record what Steam currently displays" calls for and what
is reported here, no more.

**Authorized next action:** None under P0-B1A.

## Sanitization

All process-evidence text was produced from raw `ps`/`/proc` reads and passed through
`tools/inventory/linux/redact_process_evidence.py` (new in this rung, extends
`tools/inventory/linux/sanitize.py`'s `Sanitizer`) before being written to any committed file.
Every value it substitutes is derived from the live environment at run time — the real home
directory, Steam library path, MCC install root, Proton prefix, and local Steam account id(s) are
never typed as literal arguments into the sanitizing command, so they cannot leak through shell
history or a mistyped command either.

Placeholders used in this rung's evidence, per this task's authorization:

- `<HOME>` — the operator's home directory, in both its symlinked and `realpath`-resolved forms
  (same ostree-symlink caveat as P0-B1: `/home` → `/var/home`).
- `<MCC_INSTALL_ROOT>` — the MCC install directory (`steamapps/common/Halo The Master Chief
  Collection`).
- `<MCC_PROTON_PREFIX>` — `steamapps/compatdata/976730/pfx` (new placeholder this rung;
  `sanitize.py`'s `Sanitizer` gained a `proton_prefix` parameter to support it, kept optional and
  backward-compatible with P0-B1's existing call site).
- `<STEAM_LIBRARY>` — the Steam library root (`.local/share/Steam`) itself, applied before the
  `<HOME>` replacement so the far more common `steamapps/common/...`, `ubuntu12_32/...`, etc.
  fragments collapse to one placeholder instead of repeating `<HOME>/.local/share/Steam/...` in
  every line (new placeholder this rung, same backward-compatible extension).
- `<ACCOUNT_IDENTIFIER_REDACTED>` — the local Steam account id under `userdata/` (this rung's
  `Sanitizer` call overrides the default `<STEAM_ACCOUNT_ID>` placeholder name via the new
  `account_id_placeholder` parameter, per this task's requested placeholder set; P0-B1's own
  already-committed evidence is unchanged).
- `<STEAMID64>` — any SteamID64-shaped number (`7656119` + 10 digits), as in P0-B1, kept as a
  pattern-based safety net.

**No real SteamID64 value appears anywhere in this rung's commands, reports, fixtures, or
output** — verified by grep (see "Validation" below); the account-id placeholder mechanism used
the account id discovered by enumerating `userdata/` at run time, never a hardcoded literal.

Confirmed by direct grep of every file this rung adds, for: the real home path in both forms,
the real Steam account id, any SteamID64-shaped number, and the machine hostname — zero matches
for all four (see "Validation").

## Requires manual interaction (performed under this rung, recorded here for traceability)

Every item P0-B1's report listed as "requires manual interaction" was addressed:

1. Steam Properties → Betas tab — checked directly (Claim 1); no branch besides the default is
   offered.
2. A confirmed default-mode launch, with process/behavior evidence — performed (Claims 3–5).
3. An EAC-disabled launch — not performed, because none is offered (Claim 2); no launch was
   manufactured to force one, per this rung's hard boundary.

**P0-B2 (native Windows) remains unauthorized and unstarted.** P0-C was not started.

## Test results

```
.venv/bin/python -m pytest -q
```

Full suite result, new tests, and `git diff --check` output are recorded under "Validation" in
this rung's commit — see the completion report delivered alongside this commit for exact counts.

## Next gate

Per `docs/ROADMAP.md` and `docs/STATUS.md`, P0-B1A is one interactive-validation rung within
P0-B; it does not itself close P0-B (P0-B2, native Windows, remains open) and does not authorize
P0-C. Each later rung requires its own explicit authorization.
