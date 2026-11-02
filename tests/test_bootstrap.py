from __future__ import annotations

import asyncio
import io
import tarfile
from pathlib import Path

import pytest

from BOT import bootstrap
from BOT import i18n
from BOT.config import ConfigError
from BOT.config import Config
from BOT.bootstrap import (
    CHECK_SCRIPT,
    ENV_FILE,
    INSTALL_DIR,
    REFUSAL,
    UNIT_PATH,
    BootstrapError,
    BootstrapPlan,
    check_plan,
    check_root,
    format_checks,
    install_script,
    parse_args,
    payload_archive,
    plan_from,
    unit_text,
    verify_admin,
)
from BOT.shell import ShellError, ShellOutput


def plan(**kw) -> BootstrapPlan:
    base = dict(token="123:ABC", api_id=12345, api_hash="0" * 32, admin_id=777)
    base.update(kw)
    return BootstrapPlan(**base)


def test_root_check_accepts_root() -> None:
    assert check_root(0) is None


def test_root_check_refuses_user() -> None:
    with pytest.raises(BootstrapError) as info:
        check_root(1000)
    assert info.value.message == REFUSAL
    assert "root" in info.value.message


def test_verify_admin_empty_expected_claims() -> None:
    ok, admin, message = verify_admin(4242, 0)
    assert ok is True
    assert admin == 4242
    assert message == i18n.t("BOOT_ID_PINNED")


def test_verify_admin_match() -> None:
    ok, admin, message = verify_admin(777, 777)
    assert ok is True
    assert admin == 777
    assert message == i18n.t("BOOT_ID_MATCH")


def test_verify_admin_mismatch() -> None:
    ok, admin, message = verify_admin(1, 777)
    assert ok is False
    assert admin == 777
    assert message == i18n.t("BOOT_ID_MISMATCH", who=1, want=777)


def test_verify_admin_missing_id() -> None:
    ok, admin, message = verify_admin(0, 777)
    assert ok is False
    assert admin == 777
    assert message == i18n.t("BOOT_ID_NONE")


def test_parse_args_flags() -> None:
    args = parse_args(["--ssh-host", "1.2.3.4", "--admin-id=5", "--dev"])
    assert args["ssh_host"] == "1.2.3.4"
    assert args["admin_id"] == "5"
    assert args["dev"] is True


def test_plan_from_args() -> None:
    args = parse_args(["--token", "t", "--api-id", "1", "--api-hash", "x", "--admin-id", "9"])
    built = plan_from(args)
    assert built.token == "t"
    assert built.api_id == 1
    assert built.admin_id == 9
    assert built.install_dir == INSTALL_DIR


def test_plan_from_defaults() -> None:
    built = plan_from({})
    assert built.settings().port == 22
    assert built.dev is False
    assert built.state_dir == bootstrap.STATE_DIR


def test_settings_hold_no_credentials() -> None:
    cfg = plan().settings()
    assert cfg.port == 22
    assert cfg.is_ready() is True
    for name in ("host", "user", "password", "key", "passphrase", "sudo_password", "auth", "mode", "fingerprint"):
        assert not hasattr(cfg, name), name


def test_env_text_contains_all_keys() -> None:
    text = plan().env_text()
    for token in ("BOT_TOKEN=123:ABC", "API_ID=12345", "ADMIN_ID=777", "OBHOD_STATE_DIR="):
        assert token in text


def test_install_script_deps_phase() -> None:
    script = install_script(plan(), "deps")
    assert "set -euo pipefail" in script
    assert 'if [ "$(id -u)" != "0" ]' in script
    assert 'command -v "$PY"' in script
    assert "venv" in script
    assert "requirements.txt" in script
    assert "OBHODENV" not in script


def test_install_script_finalize_phase() -> None:
    script = install_script(plan(), "finalize")
    assert "OBHODENV" in script
    assert "BOT_TOKEN=123:ABC" in script
    assert UNIT_PATH in script
    assert "systemctl restart obhod.service" in script
    assert i18n.t("BOOT_UNIT_MANUAL") in script
    assert i18n.t("BOOT_UNIT_STARTED") in script


def test_install_script_has_no_comments() -> None:
    for phase in ("deps", "finalize"):
        for line in install_script(plan(), phase).splitlines():
            assert not line.strip().startswith("#")


def test_unit_text() -> None:
    body = unit_text(plan())
    assert "[Service]" in body
    assert "ExecStart=/opt/obhod/.venv/bin/python -m BOT" in body
    assert f"EnvironmentFile={ENV_FILE}" in body
    assert "WantedBy=multi-user.target" in body


def test_payload_archive_contains_bot() -> None:
    blob = payload_archive()
    assert len(blob) > 1000
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as bundle:
        names = bundle.getnames()
    assert any(name.startswith("BOT/") for name in names)
    assert any(name == "Storage/remote/xray_agent.py" for name in names)
    assert "requirements.txt" in names
    assert not any("__pycache__" in name for name in names)
    assert not any(name.startswith("tests/") for name in names)


def test_payload_archive_is_deterministic_enough() -> None:
    first = payload_archive()
    second = payload_archive()
    assert len(first) == len(second)


def _tiny_archive() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        data = b"ok"
        info = tarfile.TarInfo("marker.txt")
        info.size = len(data)
        bundle.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class FakeShell:
    def __init__(self, code: int = 0, text: str = "done") -> None:
        self.code = code
        self.text = text
        self.commands: list[list[str]] = []
        self.stdins: list[bytes] = []

    async def run_argv(self, argv, stdin=None, timeout=None):
        self.commands.append(list(argv))
        self.stdins.append(stdin or b"")
        return ShellOutput(text=self.text, code=self.code)


def test_bootstrap_happy_path() -> None:
    shell = FakeShell()
    plan_value = plan()
    steps = asyncio.run(bootstrap.bootstrap(plan_value, shell=shell, payload=b"payload"))
    assert i18n.t("BOOT_STEP_ROOT") in steps
    assert i18n.t("BOOT_ID_MATCH") in steps
    assert steps[-1] == i18n.t("BOOT_STEP_NEXT")
    assert len(shell.commands) == 4
    assert shell.commands[1][:3] == ["/bin/tar", "-xzf", "-"]
    assert shell.stdins[1] == b"payload"


def test_plan_has_no_credentials() -> None:
    value = plan()
    for name in ("host", "user", "password", "key", "passphrase", "sudo_password", "auth", "mode"):
        assert not hasattr(value, name), name
    assert value.settings().port == 22


def test_bootstrap_requires_token() -> None:
    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.bootstrap(plan(token=""), shell=FakeShell(), payload=b"x"))
    assert "token" in info.value.message


def test_bootstrap_fails_on_push_error() -> None:
    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.bootstrap(plan(), shell=FakeShell(code=1, text="no space"), payload=b"x"))
    assert "no space" in info.value.message


def test_bootstrap_blocks_on_admin_mismatch() -> None:
    shell = FakeShell()

    async def confirm() -> int:
        return 5

    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.bootstrap(plan(), shell=shell, payload=b"x", confirm=confirm))
    assert info.value.message == i18n.t("BOOT_ID_MISMATCH", who=5, want=plan().admin_id)
    assert len(shell.commands) == 3


def test_bootstrap_claims_admin_when_empty() -> None:
    shell = FakeShell()

    async def confirm() -> int:
        return 1234

    plan_value = plan(admin_id=0)
    steps = asyncio.run(bootstrap.bootstrap(plan_value, shell=shell, payload=b"x", confirm=confirm))
    assert plan_value.admin_id == 1234
    assert i18n.t("BOOT_ID_PINNED") in steps


def test_bootstrap_sync_confirm() -> None:
    shell = FakeShell()
    steps = asyncio.run(bootstrap.bootstrap(plan(admin_id=0), shell=shell, payload=b"x", confirm=lambda: 55))
    assert steps
    assert shell.commands


def test_bootstrap_reports_steps() -> None:
    seen: list[str] = []
    asyncio.run(bootstrap.bootstrap(plan(), shell=FakeShell(), payload=b"x", on_step=seen.append))
    assert len(seen) == 7
    assert seen[0] == i18n.t("BOOT_STEP_ROOT")


def test_bootstrap_propagates_ssh_error() -> None:

    class BrokenShell:
        async def run_argv(self, argv, stdin=None, timeout=None):
            raise ShellError("no interpreter")

    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.bootstrap(plan(), shell=BrokenShell(), payload=b"x"))
    assert "no interpreter" in info.value.message


def test_bootstrap_finalize_error() -> None:
    class HalfShell(FakeShell):
        def __init__(self) -> None:
            FakeShell.__init__(self)
            self.count = 0

        async def run_argv(self, argv, stdin=None, timeout=None):
            self.count += 1
            self.commands.append(list(argv))
            self.stdins.append(stdin or b"")
            if self.count > 3:
                return ShellOutput(text="the service did not start", code=1)
            return ShellOutput(text="ok", code=0)

    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.bootstrap(plan(), shell=HalfShell(), payload=b"x"))
    assert "the service did not start" in info.value.message


def test_run_refuses_without_root(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 1000)
    code = bootstrap.run(["--ssh-host", "127.0.0.1"])
    assert code == 1
    assert REFUSAL in capsys.readouterr().err


def test_payload_items_cover_repo() -> None:
    root = Path(__file__).resolve().parent.parent
    for name in bootstrap.PAYLOAD_ITEMS:
        assert (root / name).exists(), name


def test_run_script_true_via_the_local_shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from BOT.shell import LocalShell

    monkeypatch.setattr("BOT.shell.os.geteuid", lambda: 0)
    shell = LocalShell(command_timeout=60)
    out = asyncio.run(bootstrap.run_script(shell, "printf '%s\\n' done\n"))
    assert out.code == 0
    assert "done" in out.text

    target = tmp_path / "opt"
    blob = _tiny_archive()
    files = asyncio.run(
        bootstrap.push_files(shell, blob, plan(install_dir=str(target), state_dir=str(tmp_path / "state")))
    )
    assert files.code == 0
    assert (target / "marker.txt").read_text(encoding="utf-8") == "ok"


CHECK_OK = (
    "root=yes\n"
    "python=3.13.1\n"
    "systemd=yes\n"
    "tar=yes\n"
    "disk=8388608\n"
    "github=yes\n"
    "telegram=yes\n"
    "check done\n"
)


def test_check_script_has_no_comments() -> None:
    assert "#" not in CHECK_SCRIPT


def test_check_script_runs_bash_syntax() -> None:
    import subprocess

    result = subprocess.run(["bash", "-n"], input=CHECK_SCRIPT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_check_plan_reports_success() -> None:
    checks = asyncio.run(check_plan(FakeShell(text=CHECK_OK), plan()))
    assert [item[0] for item in checks] == [
        i18n.t("BOOT_CHK_ROOT"),
        i18n.t("BOOT_CHK_PYTHON"),
        i18n.t("BOOT_CHK_SYSTEMD"),
        i18n.t("BOOT_CHK_TAR"),
        i18n.t("BOOT_CHK_DISK"),
        i18n.t("BOOT_CHK_GITHUB"),
        i18n.t("BOOT_CHK_TELEGRAM"),
    ]
    assert all(item[1] for item in checks)


def test_check_plan_flags_missing_python() -> None:
    text = CHECK_OK.replace("python=3.13.1", "python=none")
    checks = asyncio.run(check_plan(FakeShell(text=text), plan()))
    python = [item for item in checks if item[0] == "python3"][0]
    assert python[1] is False
    assert python[2] == "none"


def test_check_plan_flags_root_and_disk() -> None:
    text = CHECK_OK.replace("root=yes", "root=no").replace("disk=8388608", "disk=1024")
    checks = asyncio.run(check_plan(FakeShell(text=text), plan()))
    root = [item for item in checks if item[0] == i18n.t("BOOT_CHK_ROOT")][0]
    disk = [item for item in checks if item[0] == i18n.t("BOOT_CHK_DISK")][0]
    assert root[1] is False
    assert disk[1] is False
    assert disk[2] == i18n.t("BOOT_DISK_GB", value="0.0")


def test_format_checks_lines() -> None:
    lines = format_checks([(i18n.t("BOOT_CHK_ROOT"), True, "yes"), ("python3", False, "none")])
    assert lines == [i18n.t("BOOT_MARK_OK") + " " + i18n.t("BOOT_CHK_ROOT") + ": yes", i18n.t("BOOT_MARK_NO") + " python3: none"]


def test_check_only_returns_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    shell = FakeShell(text=CHECK_OK)
    code = asyncio.run(bootstrap.check_only(plan(), shell=shell))
    assert code == 0
    assert shell.commands[0][:2] == ["/bin/bash", "-s"]


def test_check_only_returns_one_for_missing_python() -> None:
    shell = FakeShell(text=CHECK_OK.replace("python=3.13.1", "python=none"))
    code = asyncio.run(bootstrap.check_only(plan(), shell=shell))
    assert code == 1


def test_check_only_reports_a_shell_error() -> None:
    class BrokenShell:
        async def run_argv(self, argv, stdin=None, timeout=None):
            raise ShellError("the command did not finish within 180 seconds")

    with pytest.raises(BootstrapError) as info:
        asyncio.run(bootstrap.check_only(plan(), shell=BrokenShell()))
    assert "did not finish" in info.value.message


def test_parse_args_check_flag() -> None:
    args = parse_args(["--token", "123:ABC", "--check"])
    assert args["check"] is True
    assert plan_from(args).check is True


def test_the_entry_point_reports_a_broken_configuration(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    from BOT import main as entry

    def boom(*_args: object, **_kwargs: object) -> None:
        raise ConfigError("BOT_TOKEN is required")

    monkeypatch.setattr(entry.Config, "load", boom)
    assert asyncio.run(entry.amain()) == 2
    assert "BOT_TOKEN is required" in capsys.readouterr().err


def test_the_entry_point_cleans_up_after_a_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    from BOT import main as entry

    cfg = Config(bot_token="123:abc", api_id=1, api_hash="x", admin_id=7, state_dir=Path("/tmp"), log_level="INFO")
    monkeypatch.setattr(entry.Config, "load", lambda: cfg)

    class FakeBot:
        def __init__(self, _cfg: object) -> None:
            self.app = None

        async def run(self) -> None:
            await asyncio.sleep(0)

    monkeypatch.setattr(entry, "Bot", FakeBot)
    assert asyncio.run(entry.amain()) == 0


def test_the_entry_point_fails_when_the_bot_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from BOT import main as entry

    cfg = Config(bot_token="123:abc", api_id=1, api_hash="x", admin_id=7, state_dir=Path("/tmp"), log_level="INFO")
    monkeypatch.setattr(entry.Config, "load", lambda: cfg)

    class Broken:
        def __init__(self, _cfg: object) -> None:
            self.app = None

        async def run(self) -> None:
            raise RuntimeError("the loop died")

    monkeypatch.setattr(entry, "Bot", Broken)
    assert asyncio.run(entry.amain()) == 1


def test_the_logging_setup_accepts_any_level() -> None:
    from BOT import main as entry

    entry.setup_logging("not-a-level")
    entry.setup_logging("debug")
