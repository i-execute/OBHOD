from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import antiddos, cores, i18n, notify
from .models import SshSettings
from .freeturn import FtState
from .xray import SUB_PORT, XrayState

DEFAULT_TAIL = 200
TRAFFIC_NAME = 64
SCHEMA = 8

CORES = cores.keys()


class StoreError(Exception):
    pass


@dataclass
class State:
    ssh: SshSettings = field(default_factory=SshSettings)
    admin_id: int = 0
    log_tail: int = DEFAULT_TAIL
    schema: int = SCHEMA
    sub_port: int = SUB_PORT
    last_probe: dict[str, Any] = field(default_factory=dict)
    language: str = i18n.DEFAULT_LANGUAGE
    traffic: dict[str, Any] = field(default_factory=dict)
    xray: XrayState = field(default_factory=XrayState)
    freeturn: FtState = field(default_factory=FtState)
    core: str = "xray"
    emoji: bool = False
    notify: dict[str, Any] = field(default_factory=dict)
    ddos: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": int(self.schema),
            "ssh": self.ssh.to_dict(),
            "admin_id": int(self.admin_id),
            "log_tail": int(self.log_tail),
            "sub_port": int(self.sub_port),
            "last_probe": dict(self.last_probe),
            "language": i18n.normalize(self.language),
            "traffic": {str(key)[:TRAFFIC_NAME]: dict(value) for key, value in list(self.traffic.items())[:4096] if isinstance(value, dict)},
            "xray": self.xray.to_dict(),
            "freeturn": self.freeturn.to_dict(),
            "core": self.core if self.core in CORES else "xray",
            "emoji": bool(self.emoji),
            "notify": notify.Settings.from_dict(self.notify).to_dict(),
            "ddos": antiddos.Policy.from_dict(self.ddos).to_dict(),
        }

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "State":
        data = raw or {}
        state = State(
            ssh=SshSettings.from_dict(data.get("ssh")),
            admin_id=int(data.get("admin_id", 0) or 0),
            log_tail=int(data.get("log_tail", DEFAULT_TAIL) or DEFAULT_TAIL),
            schema=int(data.get("schema", SCHEMA) or SCHEMA),
            sub_port=int(data.get("sub_port", SUB_PORT) or SUB_PORT),
            last_probe=dict(data.get("last_probe") or {}),
            language=i18n.normalize(data.get("language", i18n.DEFAULT_LANGUAGE)),
            traffic={str(key)[:TRAFFIC_NAME]: dict(value) for key, value in list((data.get("traffic") or {}).items())[:4096] if isinstance(value, dict)} if isinstance(data.get("traffic"), dict) else {},
            xray=XrayState.from_dict(data.get("xray")),
            freeturn=FtState.from_dict(data.get("freeturn")),
            core=str(data.get("core", "xray") or "xray"),
            emoji=bool(data.get("emoji", False)),
            notify=notify.Settings.from_dict(data.get("notify")).to_dict(),
            ddos=antiddos.Policy.from_dict(data.get("ddos")).to_dict(),
        )
        if state.core not in CORES:
            state.core = "xray"
        state.xray.sub_port = state.sub_port
        return state


class Store:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load(self) -> State:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return State()
        if not isinstance(raw, dict):
            return State()
        return State.from_dict(raw)

    def save(self, state: State) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        payload = json.dumps(state.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        handle, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".state-", suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except OSError as exc:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise StoreError("the state file could not be written: %s" % exc) from None
