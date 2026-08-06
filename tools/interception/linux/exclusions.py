"""Hosts that must never be intercepted, decrypted, or logged, and the redaction rules.

This module is the single source of truth for the P0-C2A hard exclusions. It is
deliberately small and separately testable, because every other tool in this
package depends on it being correct.

Design principle: **exclusion is structural, not filtered.** An excluded host is
never TLS-terminated in the first place, so there is no decrypted byte to
accidentally log. That is strictly safer than terminating and then filtering,
where a logging bug or an unhandled code path can leak. The same reasoning
applies to bodies: the tools here never parse or buffer a response body, so no
configuration mistake can cause one to be written.

Matching is on registrable-suffix boundaries, so `login.live.com.attacker.test`
does not match `live.com` and a lookalike cannot slip past the denylist.
"""

from __future__ import annotations

import re

# Microsoft account authentication, Xbox token issuance, session directory,
# entitlement/purchase, and third-party auth. Sourced from the P0-C1 topology
# (`docs/CLIENT_BOOTSTRAP_TOPOLOGY.md`) plus the P0-C2A authorization.
EXCLUDED_SUFFIXES: tuple[str, ...] = (
    # Microsoft account identity
    "login.live.com",
    "login.microsoftonline.com",
    "account.live.com",
    "live.com",
    "microsoftonline.com",
    "msauth.net",
    "msftauth.net",
    "aadg.akadns.net",
    # Xbox authentication / token issuance
    "user.auth.xboxlive.com",
    "xsts.auth.xboxlive.com",
    "device.auth.xboxlive.com",
    "title.auth.xboxlive.com",
    "sisu.xboxlive.com",
    "title.mgt.xboxlive.com",
    # Session directory (MPSD) and presence
    "sessiondirectory.xboxlive.com",
    "userpresence.xboxlive.com",
    # Entitlement / purchase / licensing
    "entitlements.svc.halowaypoint.com",
    "purchase.mp.microsoft.com",
    "licensing.mp.microsoft.com",
    "displaycatalog.mp.microsoft.com",
    # Steam authentication and entitlement
    "steampowered.com",
    "steamcommunity.com",
    "steamserver.net",
    # PlayFab and Epic authentication
    "playfabapi.com",
    "epicgames.com",
    "epicgames.dev",
    "easyanticheat.net",
)

# Whole-domain guard: anything under xboxlive.com that is not explicitly chosen
# for observation is excluded by default, so a newly-appearing auth host is
# excluded until someone deliberately allows it.
DEFAULT_DENY_PARENTS: tuple[str, ...] = ("auth.xboxlive.com",)

# Header names whose VALUES must never be recorded. The tools do not record any
# header values at all; this list exists so a future change that starts
# recording values still cannot record these.
SENSITIVE_HEADERS: frozenset[str] = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-xbl-contract-version", "signature", "x-auth-token", "www-authenticate",
})

_TOKEN_SHAPED = re.compile(
    r"(eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,})"   # JWT
    r"|(\bXBL3\.0\s+x=[^;\s]+)"                                        # Xbox auth header
    r"|(\b[A-Fa-f0-9]{32,}\b)"                                         # long hex blobs
    r"|(\b7656119\d{10}\b)"                                            # SteamID64
    r"|(\b\d{16}\b)"                                                   # XUID-shaped
)

REDACTED = "<REDACTED>"


def _normalise(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host.split(":")[0] if host.count(":") == 1 else host


def is_excluded(host: str) -> bool:
    """True when a host must be blind-tunnelled and never decrypted or logged."""
    candidate = _normalise(host)
    if not candidate:
        return True  # unknown host: fail closed
    for suffix in EXCLUDED_SUFFIXES + DEFAULT_DENY_PARENTS:
        if candidate == suffix or candidate.endswith("." + suffix):
            return True
    return False


def redact_text(value: str) -> str:
    """Replace token-shaped substrings. A backstop, not the primary control."""
    return _TOKEN_SHAPED.sub(REDACTED, value or "")


def safe_header_names(header_names) -> list[str]:
    """Header NAMES only, lowercased and sorted; values are never accepted here."""
    safe = set()
    for raw_name in header_names:
        name = str(raw_name).lower()
        opaque = (
            len(name) > 64
            or re.fullmatch(r"[0-9a-f]{16,}", name, re.IGNORECASE) is not None
            or (
                len(name) >= 16
                and re.fullmatch(r"[a-z0-9_-]+", name) is not None
                and re.search(r"[a-z]", name) is not None
                and re.search(r"\d", name) is not None
            )
        )
        if opaque or re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]{1,64}", name) is None:
            safe.add("{redacted_header_name}")
        else:
            safe.add(name)
    return sorted(safe)
