"""Path and identifier redaction shared by every collector in this package.

Every collector returns raw (unsanitized) Python data structures so callers
can unit test them against real paths. `sanitize_value` is applied once, at
the edge, right before anything is printed or written to disk — never
earlier, so a bug in ordering can't leak an unsanitized intermediate value.
"""

from __future__ import annotations

import re

MCC_INSTALL_ROOT_PLACEHOLDER = "<MCC_INSTALL_ROOT>"
HOME_PLACEHOLDER = "<HOME>"
STEAM_ACCOUNT_ID_PLACEHOLDER = "<STEAM_ACCOUNT_ID>"
STEAMID64_PLACEHOLDER = "<STEAMID64>"

_STEAMID64_RE = re.compile(r"\b7656119\d{10}\b")


class Sanitizer:
    """Replaces known-sensitive substrings with stable placeholders.

    Order matters: the MCC install root is replaced before the home
    directory, since the install root is itself nested under home and would
    otherwise never match once the shorter prefix is gone.
    """

    def __init__(self, mcc_install_root: str, home: str | list[str], steam_account_ids: list[str] | None = None):
        self._replacements: list[tuple[str, str]] = []
        if mcc_install_root:
            self._replacements.append((mcc_install_root.rstrip("/"), MCC_INSTALL_ROOT_PLACEHOLDER))
        for account_id in steam_account_ids or []:
            self._replacements.append((f"/userdata/{account_id}/", f"/userdata/{STEAM_ACCOUNT_ID_PLACEHOLDER}/"))
            self._replacements.append((account_id, STEAM_ACCOUNT_ID_PLACEHOLDER))
        # A symlinked $HOME (e.g. /home/<user> -> /var/home/<user> on ostree-based
        # distros) means paths on disk may be observed in either form; replace the
        # longer/more specific form first so a shared prefix can't shadow it.
        home_variants = [home] if isinstance(home, str) else list(home)
        for variant in sorted({v.rstrip("/") for v in home_variants if v}, key=len, reverse=True):
            self._replacements.append((variant, HOME_PLACEHOLDER))

    def text(self, value: str) -> str:
        out = value
        for needle, placeholder in self._replacements:
            if needle:
                out = out.replace(needle, placeholder)
        out = _STEAMID64_RE.sub(STEAMID64_PLACEHOLDER, out)
        return out

    def value(self, obj):
        """Recursively sanitize strings inside dicts/lists/tuples; pass other types through."""
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {self.value(k): self.value(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.value(v) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self.value(v) for v in obj)
        return obj
