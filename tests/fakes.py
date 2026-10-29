from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from BOT.app import Bot
from BOT.guard import BanState, SshState
from BOT.store import State
from BOT.xray import XrayState, new_inbound


class FakeEvent:
    def __init__(self, **kwargs: Any) -> None:
        self.chat_id = kwargs.get("chat_id", 1)
        self.msg_id = kwargs.get("msg_id", 0)
        self.from_id = kwargs.get("from_id", 7)
        self.data = kwargs.get("data", "")
        self.text = kwargs.get("text", "")
        self.cmd = kwargs.get("cmd", "")
        self.query = kwargs.get("query", "")
        self.src = kwargs.get("src", "mt")
        self.update_type = kwargs.get("update_type", "")
        self.raw = kwargs.get("raw", {})
        self.answers: list[Any] = []
        self.results: list[dict] = []

    async def answer(self, text: str = "", alert: bool = False, results: list[dict] | None = None, cache_time: int = 0, **kw: Any) -> None:
        self.answers.append(
            {
                "text": text,
                "alert": alert,
                "results": results,
                "cache_time": cache_time,
                "is_personal": kw.get("is_personal"),
            }
        )
        if results is not None:
            self.results = results


class FakeApp:
    def __init__(self) -> None:
        self.deleted: list[tuple[int, int]] = []

    async def delete_msg(self, chat_id: int, msg_ids: int | list[int], **kw: Any) -> None:
        items = msg_ids if isinstance(msg_ids, list) else [msg_ids]
        for item in items:
            self.deleted.append((int(chat_id), int(item)))


class FakeControl:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.core = {
            "installed": True,
            "version": "26.10.21",
            "pinned": "v26.10.21",
            "core_path": "/usr/local/bin/xray",
            "config_path": "/usr/local/etc/xray/config.json",
            "config_exists": True,
            "config_digest": "abc",
            "inbounds": 1,
            "port": 443,
            "ports": [443],
            "listening": [443],
            "service": "active",
            "unit": True,
            "systemd": True,
            "arch": "x86_64",
            "asset": "64",
        }

    def _state(self) -> Any:
        from BOT.xrayrpc import CoreState

        return CoreState.from_dict(self.core)

    async def probe(self, cfg: Any) -> Any:
        self.calls.append(["probe"])
        return self._state()

    async def install_core(self, cfg: Any, version: str = "", url: str = "", sha256: str = "", force: bool = False) -> Any:
        from BOT.xrayrpc import XrayResponse

        self.calls.append(["install-core", version])
        return XrayResponse(result="ok", data=dict(self.core), logs=["installed"])

    async def apply(self, cfg: Any, config: str, version: str = "", restart: bool = True) -> Any:
        self.calls.append(["apply", config])
        return self._state()

    async def restart(self, cfg: Any) -> Any:
        self.calls.append(["restart"])
        return self._state()

    async def stop(self, cfg: Any) -> Any:
        self.calls.append(["stop"])
        return self._state()

    async def start(self, cfg: Any) -> Any:
        self.calls.append(["start"])
        return self._state()

    async def logs(self, cfg: Any, tail: int = 120) -> list[str]:
        self.calls.append(["logs", str(tail)])
        return ["line one", "line two"]

    async def x25519(self, cfg: Any) -> tuple[str, str]:
        self.calls.append(["x25519"])
        return "PRIVATEKEY", "PUBLICKEY"

    async def mldsa65(self, cfg: Any) -> tuple[str, str]:
        self.calls.append(["mldsa65"])
        return "SEEDVALUE", "VERIFYVALUE"

    async def vlessenc(self, cfg: Any) -> dict[str, str]:
        self.calls.append(["vlessenc"])
        return {"decryption": "mlkem768x25519plus.native.600s.key", "encryption": "mlkem768x25519plus.native.0rtt.verify"}

    async def uninstall(self, cfg: Any, purge: bool = True) -> Any:
        from BOT.xrayrpc import XrayResponse

        self.calls.append(["uninstall"])
        return XrayResponse(result="ok", data={"removed": ["unit"]})

    async def sub_install(self, cfg: Any, port: int = 2096) -> Any:
        from BOT.xrayrpc import SubState

        self.calls.append(["sub-install", str(port)])
        return SubState(installed=True, port=port, listening=False, entries=0)

    async def sub_sync(self, cfg: Any, registry: dict[str, Any], port: int = 2096) -> Any:
        from BOT.xrayrpc import SubState

        self.calls.append(["sub-sync", str(port), str(len(registry.get("entries") or {}))])
        return SubState(installed=True, port=port, listening=True, entries=len(registry.get("entries") or {}))

    async def sub_status(self, cfg: Any, port: int = 2096) -> Any:
        from BOT.xrayrpc import SubState

        self.calls.append(["sub-status"])
        return SubState(installed=True, port=port, listening=True, entries=1)

    async def sub_stop(self, cfg: Any, port: int = 2096) -> Any:
        from BOT.xrayrpc import SubState

        self.calls.append(["sub-stop"])
        return SubState(installed=True, port=port, listening=False, entries=1)


class FakeGuard:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def install(
        self,
        cfg: Any,
        port: int = 0,
        bantime: int = 30,
        findtime: int = 1920,
        maxretry: int = 1,
        logpath: str = "",
        ssh: bool = True,
        ssh_bantime: str = "3d",
        ssh_maxretry: int = 3,
        ignoreip: str = "127.0.0.1/8 ::1",
    ) -> BanState:
        self.calls.append("install")
        return BanState(installed=True, jails=["obhod-ipl", "obhod-sshd"], banned=["1.2.3.4"], port=port)

    async def remove(self, cfg: Any, port: int = 0) -> BanState:
        self.calls.append("remove")
        return BanState(installed=True, jails=[], banned=[])

    async def status(self, cfg: Any, port: int = 0) -> BanState:
        self.calls.append("status")
        return BanState(installed=True, jails=["obhod-ipl"], banned=["5.6.7.8"], port=port)

    async def ban(self, cfg: Any, address: str, port: int = 0) -> BanState:
        self.calls.append("ban")
        return BanState(installed=True, jails=["obhod-ipl"], banned=[address])

    async def unban(self, cfg: Any, address: str, port: int = 0) -> BanState:
        self.calls.append("unban")
        return BanState(installed=True, jails=["obhod-ipl"], banned=[])

    async def ssh_status(self, cfg: Any) -> SshState:
        self.calls.append("ssh_status")
        return SshState(
            ports=[22],
            permit_root_login="prohibit-password",
            service="active",
            keys=1,
            key_user="root",
            key_path="/root/.ssh/authorized_keys",
            key_list=[{"type": "ssh-ed25519", "comment": "laptop", "fingerprint": "SHA256:abc", "bytes": 68}],
        )

    async def ssh_apply(self, cfg: Any, port: int = 0, password: str = "", root: str = "") -> SshState:
        self.calls.append("ssh_apply")
        return SshState(ports=[port or 22], password_authentication=password or "yes", service="active")

    async def ssh_add_key(self, cfg: Any, public_key: str) -> SshState:
        self.calls.append("ssh_add_key")
        return SshState(ports=[22], keys=2)

    async def ssh_remove(self, cfg: Any) -> SshState:
        self.calls.append("ssh_remove")
        return SshState(ports=[22], dropin_exists=False)


class FakeFtControl:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.fail = ""
        self.key = "c" * 64

    def _link(self, name: str) -> str:
        from BOT.freeturn import encode_link

        return encode_link(
            {
                "v": 1,
                "provider": "vk",
                "peer": "203.0.113.10:56123",
                "obf": "rtpopus3",
                "key": self.key,
                "cid": "0123456789abcdef0123456789abcdef",
                "name": name,
            }
        )

    def _conf(self) -> str:
        import base64

        body = "[Interface]\nPrivateKey = abc\nMTU = 1420\n# note\n\n[Peer]\nPublicKey = def\n"
        return base64.b64encode(body.encode("utf-8")).decode("ascii")

    async def probe(self) -> Any:
        from BOT.freeturn import FtState

        self.calls.append(["probe"])
        return FtState.from_dict(
            {
                "installed": True,
                "running": True,
                "euid": 0,
                "arch": "x86_64",
                "method": "systemd",
                "version": "v4.1.1",
                "config": {
                    "method": "systemd",
                    "backend": "new",
                    "listen_port": 56123,
                    "mode": "udp",
                    "obf_profile": "rtpopus3",
                    "obf_key": self.key,
                    "version": "latest",
                },
            }
        )

    async def apply(self, config: Any, update: bool = False, obf_key: str = "") -> Any:
        from BOT.freeturn import FtState

        self.calls.append(["apply", config.method, str(config.listen_port), obf_key])
        return FtState.from_dict(
            {
                "installed": True,
                "running": True,
                "euid": 0,
                "arch": "x86_64",
                "method": config.method,
                "version": "v4.1.1",
                "config": dict(config.to_dict(), obf_key=self.key),
            }
        )

    async def stop(self) -> Any:
        from BOT.freeturn import FtResponse

        self.calls.append(["stop"])
        return FtResponse(result="ok", data={"stopped": True})

    async def restart(self) -> Any:
        from BOT.freeturn import FtResponse

        self.calls.append(["restart"])
        return FtResponse(result="ok", data={"running": True})

    async def logs(self, tail: int = 120) -> list[str]:
        self.calls.append(["logs", str(tail)])
        return ["line one", "line two"]

    async def client_list(self) -> Any:
        from BOT.freeturn import FtClient, FtShare

        self.calls.append(["client-list"])
        clients = [FtClient(name="owner", client_id="0123456789abcdef0123456789abcdef", owner=True)]
        share = FtShare(backend="new", host="203.0.113.10", port=56123, mode="udp", obf_profile="rtpopus3", key_present=True)
        return clients, share

    async def client_add(self, name: str) -> Any:
        from BOT.freeturn import FtClient

        self.calls.append(["client-add", name])
        return FtClient(name=name, client_id="ffeeddccbbaa99887766554433221100"), self._link(name), self._conf()

    async def client_conf(self, name: str) -> Any:
        from BOT.freeturn import FtClient

        self.calls.append(["client-conf", name])
        owner = name == "owner"
        return FtClient(name=name, client_id="0123456789abcdef0123456789abcdef", owner=owner), self._link(name), self._conf()

    async def client_remove(self, name: str) -> Any:
        from BOT.freeturn import FtError, FtResponse

        self.calls.append(["client-remove", name])
        if name == "owner":
            raise FtError("the owner client cannot be removed", "owner_protected")
        return FtResponse(result="ok", data={"removed": True})

    async def uninstall(self, target: str = "all", purge: bool = True) -> Any:
        from BOT.freeturn import FtResponse

        self.calls.append(["uninstall", target])
        return FtResponse(result="ok", data={})


def make_config(state_dir: Path) -> SimpleNamespace:
    return SimpleNamespace(
        bot_token="1:abc",
        api_id=1,
        api_hash="hash",
        admin_id=7,
        state_dir=Path(state_dir),
        session_name="test",
        dc_host=None,
        dc_port=None,
    )


def make_bot(tmp_path: Path) -> Bot:
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    bot = Bot(make_config(tmp_path), control=FakeControl(), guard=FakeGuard())
    bot.sent = []
    bot.rendered = []

    async def send(chat_id: int, rich: Any) -> None:
        bot.sent.append(rich)

    async def render(chat_id: int, msg_id: int, rich: Any) -> None:
        bot.rendered.append(rich)

    bot.send = send
    bot.render = render
    bot.app = FakeApp()
    return bot


def make_state() -> State:
    return State(xray=XrayState())


def make_inbound(security: str = "reality", network: str = "raw", port: int = 443) -> Any:
    inbound = new_inbound("vless", port, network, security)
    inbound.remark = f"{security}-{port}"
    inbound.make_client("owner")
    return inbound
