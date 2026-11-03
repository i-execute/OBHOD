from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass, field


log = logging.getLogger("obhod.audit")
MAX_EVENTS = 200
REPLAY_WINDOW = 1.0
SECRET_KEYS = ("key", "password", "secret", "token", "seed", "ident", "sub_id", "sub_key", "private")
CLEAN = re.compile(r"[^ -~]")


def clean(value: object, limit: int) -> str:
    return CLEAN.sub("", str(value or "")).strip()[:limit]


def is_secret(name: str) -> bool:
    token = str(name or "").lower()
    return any(part in token for part in SECRET_KEYS)


@dataclass
class Audit:
    events: deque = field(default_factory=lambda: deque(maxlen=MAX_EVENTS))
    recent: dict = field(default_factory=dict)
    sink: object = None

    def note(self, actor: int, action: str, outcome: str = "ok", detail: str = "") -> None:
        record = {
            "actor": int(actor or 0),
            "action": clean(action, 40),
            "outcome": clean(outcome, 20),
            "detail": clean(detail, 80),
        }
        self.events.append(record)
        if self.sink is not None:
            self.sink.note("", record["action"], "admin" if record["outcome"] == "ok" else "deny", record["actor"], record["detail"])
        log.info("audit actor=%s action=%s outcome=%s detail=%s", record["actor"], record["action"], record["outcome"], record["detail"])

    def tail(self, count: int = 20) -> list[dict]:
        items = list(self.events)
        return items[-int(count):]

    def first_time(self, actor: int, action: str, now: float) -> bool:
        key = (int(actor or 0), str(action or "")[:60])
        last = self.recent.get(key, 0.0)
        if now - last < REPLAY_WINDOW:
            self.recent[key] = now
            return False
        self.recent[key] = now
        if len(self.recent) > MAX_EVENTS * 4:
            keep = sorted(self.recent.items(), key=lambda pair: pair[1])[-MAX_EVENTS:]
            self.recent = dict(keep)
        return True
