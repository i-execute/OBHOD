from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(Exception):
    pass


def _env_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        data[key.strip()] = value
    return data


LOG_LEVELS = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")


def _float(name: str, raw: str, low: float, high: float) -> float:
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError):
        raise ConfigError(f"{name} must be a number") from None
    if value != value or value < low or value > high:
        raise ConfigError(f"{name} must be between {low:g} and {high:g}")
    return value


def _port(name: str, raw: object) -> int:
    text = str(raw or "").strip()
    if not text:
        return 0
    value = _int(name, text)
    if not 1 <= value <= 65535:
        raise ConfigError(f"{name} must be between 1 and 65535")
    return value


def _int(name: str, raw: str) -> int:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        raise ConfigError(f"{name} must be a number, got {raw!r}") from None


@dataclass(frozen=True)
class Config:
    bot_token: str
    api_id: int
    api_hash: str
    admin_id: int
    state_dir: Path
    session_name: str = "obhod"
    connect_timeout: float = 12.0
    command_timeout: float = 300.0
    apply_timeout: float = 900.0
    default_dc_host: str | None = None
    default_dc_port: int | None = None
    env_path: Path | None = None
    log_level: str = "INFO"
    emoji_default: bool = False
    sub_port: int = 0
    api_port: int = 0
    extra: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def load(env_path: str | os.PathLike[str] | None = None) -> "Config":
        path = Path(env_path or os.environ.get("OBHOD_ENV", "/etc/obhod/obhod.env"))
        values = _env_file(path)
        for key, value in os.environ.items():
            if key.startswith("OBHOD_") or key in {
                "BOT_TOKEN",
                "API_ID",
                "API_HASH",
                "ADMIN_ID",
            }:
                values[key] = value

        token = values.get("BOT_TOKEN", "").strip()
        api_hash = values.get("API_HASH", "").strip()
        api_id_raw = values.get("API_ID", "").strip()
        admin_raw = values.get("ADMIN_ID", "").strip()

        missing = [
            name
            for name, value in (
                ("BOT_TOKEN", token),
                ("API_ID", api_id_raw),
                ("API_HASH", api_hash),
            )
            if not value
        ]
        if missing:
            raise ConfigError("missing required keys: " + ", ".join(missing))
        if ":" not in token:
            raise ConfigError("BOT_TOKEN must look like 123456:ABC-DEF")

        state_dir = Path(values.get("OBHOD_STATE_DIR", "/var/lib/obhod"))
        if not state_dir.is_absolute() or ".." in state_dir.parts:
            raise ConfigError("OBHOD_STATE_DIR must be a simple absolute path")
        level = str(values.get("OBHOD_LOG_LEVEL", "INFO")).strip().upper() or "INFO"
        if level not in LOG_LEVELS:
            raise ConfigError("OBHOD_LOG_LEVEL must be one of " + ", ".join(LOG_LEVELS))

        return Config(
            bot_token=token,
            api_id=_int("API_ID", api_id_raw),
            api_hash=api_hash,
            admin_id=_int("ADMIN_ID", admin_raw) if admin_raw else 0,
            state_dir=state_dir,
            session_name=str(state_dir / values.get("OBHOD_SESSION", "obhod")),
            connect_timeout=_float("OBHOD_CONNECT_TIMEOUT", values.get("OBHOD_CONNECT_TIMEOUT", 12.0), 1.0, 120.0),
            command_timeout=_float("OBHOD_COMMAND_TIMEOUT", values.get("OBHOD_COMMAND_TIMEOUT", 300.0), 5.0, 3600.0),
            apply_timeout=_float("OBHOD_APPLY_TIMEOUT", values.get("OBHOD_APPLY_TIMEOUT", 900.0), 5.0, 3600.0),
            default_dc_host=values.get("OBHOD_DC_HOST") or None,
            default_dc_port=_int("OBHOD_DC_PORT", values["OBHOD_DC_PORT"]) if values.get("OBHOD_DC_PORT") else None,
            env_path=path,
            log_level=level,
            emoji_default=str(values.get("OBHOD_EMOJI", "")).strip().lower() in {"1", "on", "yes", "true"},
            sub_port=_port("OBHOD_SUB_PORT", values.get("OBHOD_SUB_PORT", "")),
            api_port=_port("OBHOD_API_PORT", values.get("OBHOD_API_PORT", "")),
            extra=values,
        )

    @property
    def dc_host(self) -> str | None:
        return self.default_dc_host

    @property
    def dc_port(self) -> int | None:
        return self.default_dc_port
