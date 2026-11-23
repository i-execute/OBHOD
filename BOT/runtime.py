from __future__ import annotations

import re
import subprocess

MAX_HOSTNAME = 253
_TAG_RE = re.compile(r"[^A-Za-z0-9._-]+")


def literal_hostname() -> str:
    try:
        result = subprocess.run(
            ["hostname"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    line = str(result.stdout or "").splitlines()[0].strip() if str(result.stdout or "").splitlines() else ""
    if not line or any(ord(char) < 32 or ord(char) == 127 for char in line):
        return ""
    return line[:MAX_HOSTNAME]


def subscription_tag_for(hostname: object) -> str:
    text = _TAG_RE.sub("-", str(hostname or "").strip()).strip(".-_")
    if not text:
        return "server"
    text = text[:32].strip(".-_")
    return text if text else "server"
