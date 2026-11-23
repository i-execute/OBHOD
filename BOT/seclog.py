from __future__ import annotations

import logging
import os
import re
import threading

log = logging.getLogger("obhod.security")
DEFAULT_PATH = "/var/log/obhod/security.log"
MAX_BYTES = 4 * 1024 * 1024
CLEAN = re.compile(r"[^ -~]")
SPACE = re.compile(r"\s+")
LONG_RUN = re.compile(r"[A-Za-z0-9_\-]{32,}")
OFF_VALUES = {"0", "off", "no", "false", "disabled"}


def field(value, limit):
    text = CLEAN.sub("", str(value or ""))
    text = SPACE.sub("_", text.strip())
    return text[:limit]


def redact(text):
    return LONG_RUN.sub("<redacted>", str(text or ""))


def event_line(ip, event, outcome, actor, detail):
    address = field(redact(ip), 64)
    verdict = field(outcome, 16) or "-"
    if not address and verdict in {"deny", "block"}:
        verdict = "info"
    return "security ip=%s event=%s outcome=%s actor=%s detail=%s" % (
        address or "-",
        field(event, 32) or "-",
        verdict,
        int(actor or 0),
        field(redact(detail), 120) or "-",
    )


class SecurityLog:
    def __init__(self, path=None, max_bytes=MAX_BYTES, enabled=None):
        self.path = str(path or os.environ.get("OBHOD_SECURITY_LOG", DEFAULT_PATH))
        self.max_bytes = max(4096, int(max_bytes))
        if enabled is None:
            enabled = os.environ.get("OBHOD_SECLOG", "1").strip().lower() not in OFF_VALUES
        self.enabled = bool(enabled)
        self.lock = threading.Lock()

    def line(self, ip="", event="", outcome="deny", actor=0, detail=""):
        return event_line(ip, event, outcome, actor, detail)

    def note(self, ip="", event="", outcome="deny", actor=0, detail=""):
        text = self.line(ip, event, outcome, actor, detail)
        log.info("security event=%s outcome=%s actor=%s", field(event, 32), field(outcome, 16), int(actor or 0))
        if not self.enabled:
            return False
        with self.lock:
            return self.write(text)

    def write(self, text):
        try:
            folder = os.path.dirname(self.path)
            if folder and not os.path.isdir(folder):
                os.makedirs(folder, mode=0o700, exist_ok=True)
            if os.path.islink(self.path):
                return False
            self.rotate()
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(descriptor, (text + "\n").encode("utf-8", "replace"))
            finally:
                os.close(descriptor)
            return True
        except OSError as exc:
            log.warning("the security log is not writable: %s", exc)
            return False

    def rotate(self):
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return False
        if size < self.max_bytes:
            return False
        try:
            os.replace(self.path, self.path + ".1")
            return True
        except OSError as exc:
            log.warning("the security log is not rotated: %s", exc)
            return False
