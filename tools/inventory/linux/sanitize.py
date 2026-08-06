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
MCC_PROTON_PREFIX_PLACEHOLDER = "<MCC_PROTON_PREFIX>"
STEAM_LIBRARY_PLACEHOLDER = "<STEAM_LIBRARY>"

_STEAMID64_RE = re.compile(r"\b7656119\d{10}\b")


def _variants(value: str | list[str] | None) -> list[str]:
    if not value:
        return []
    values = [value] if isinstance(value, str) else list(value)
    # A symlinked $HOME (e.g. /home/<user> -> /var/home/<user> on ostree-based
    # distros) means the same real path may appear on disk/in argv in either
    # form; replace the longer/more specific form first so a shared prefix
    # can't shadow it (see length-descending sort at each call site below).
    return sorted({v.rstrip("/") for v in values if v}, key=len, reverse=True)


class Sanitizer:
    """Replaces known-sensitive substrings with stable placeholders.

    Order matters: the most specific (longest, most deeply nested) paths are
    replaced first, since a shorter parent-path replacement would otherwise
    shadow part of a longer child path and leave a stray fragment behind.
    Nesting here, most to least specific: `mcc_install_root` and
    `proton_prefix` (siblings under the Steam library) > `steam_library` >
    `home` (steam_library's parent).
    """

    def __init__(
        self,
        mcc_install_root: str | list[str],
        home: str | list[str],
        steam_account_ids: list[str] | None = None,
        proton_prefix: str | list[str] | None = None,
        steam_library: str | list[str] | None = None,
        account_id_placeholder: str = STEAM_ACCOUNT_ID_PLACEHOLDER,
    ):
        self._replacements: list[tuple[str, str]] = []
        for variant in _variants(mcc_install_root):
            self._replacements.append((variant, MCC_INSTALL_ROOT_PLACEHOLDER))
        for variant in _variants(proton_prefix):
            self._replacements.append((variant, MCC_PROTON_PREFIX_PLACEHOLDER))
        for account_id in steam_account_ids or []:
            self._replacements.append((f"/userdata/{account_id}/", f"/userdata/{account_id_placeholder}/"))
            self._replacements.append((account_id, account_id_placeholder))
        for variant in _variants(steam_library):
            self._replacements.append((variant, STEAM_LIBRARY_PLACEHOLDER))
        for variant in _variants(home):
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
