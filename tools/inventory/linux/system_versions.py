"""Collect host/tool version strings relevant to reproducing this rung's evidence.

Every lookup is best-effort: a missing tool records `null`, not a stack
trace, since not every collection host has every tool (e.g. PowerShell is
not expected on a native Linux box; its absence is itself evidence for the
report, not a script bug).
"""

from __future__ import annotations

import platform
import re
import subprocess
from pathlib import Path

_NODENAME_PLACEHOLDER = "<HOSTNAME>"


def _run(*cmd: str) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except (FileNotFoundError, OSError):
        return None
    output = (result.stdout or result.stderr or "").strip()
    return output or None


def _read_os_release() -> dict:
    path = Path("/etc/os-release")
    if not path.is_file():
        return {}
    fields = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key] = value.strip('"').strip("'")
    return fields


def _sanitized_uname() -> str:
    parts = platform.uname()
    # nodename (parts[1]) is the machine's hostname; redact it, keep the rest.
    return f"{parts.system} {_NODENAME_PLACEHOLDER} {parts.release} {parts.version} {parts.machine}"


def _gpu_driver_versions() -> list[dict]:
    devices = []
    vulkaninfo = _run("vulkaninfo", "--summary")
    if vulkaninfo:
        block_re = re.compile(
            r"GPU(\d+):\s*\n"
            r"(?:\t.*\n)*?"
            r"\tdeviceName\s*=\s*(?P<name>.+)\n"
            r"(?:\t.*\n)*?"
            r"\tdriverID\s*=\s*(?P<driver_id>.+)\n"
            r"\tdriverName\s*=\s*(?P<driver_name>.+)\n"
            r"\tdriverInfo\s*=\s*(?P<driver_info>.+)\n"
        )
        for match in block_re.finditer(vulkaninfo):
            devices.append({
                "device_name": match.group("name").strip(),
                "driver_id": match.group("driver_id").strip(),
                "driver_name": match.group("driver_name").strip(),
                "driver_info": match.group("driver_info").strip(),
            })
    return devices


def _nvidia_smi_driver() -> str | None:
    out = _run("nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader")
    return out.splitlines()[0].strip() if out else None


def collect() -> dict:
    os_release = _read_os_release()
    return {
        "os_release": {
            "pretty_name": os_release.get("PRETTY_NAME"),
            "version": os_release.get("VERSION"),
            "version_id": os_release.get("VERSION_ID"),
            "build_id": os_release.get("BUILD_ID"),
            "image_id": os_release.get("IMAGE_ID"),
            "variant_id": os_release.get("VARIANT_ID"),
            "ostree_version": os_release.get("OSTREE_VERSION"),
        },
        "kernel": _sanitized_uname(),
        "steam_package_version": _run("rpm", "-q", "steam"),
        "nvidia_driver_version": _nvidia_smi_driver(),
        "vulkan_gpu_drivers": _gpu_driver_versions(),
        "git_version": _run("git", "--version"),
        "python_version": _run("python3", "--version"),
        "powershell_version": _run("pwsh", "--version"),
        "sha256sum_version": (_run("sha256sum", "--version") or "").splitlines()[0] or None,
    }


if __name__ == "__main__":
    import json

    print(json.dumps(collect(), indent=2))
