from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "Storage" / "obhod-install.sh"
UNIT = ROOT / "Storage" / "obhod.service"
HASH = "b" * 32


def run(args: list[str], env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    merged = dict(os.environ)
    merged.pop("OBHOD_PREFIX", None)
    merged.pop("OBHOD_ENV", None)
    if env:
        merged.update(env)
    return subprocess.run(["bash", str(INSTALLER), *args], capture_output=True, text=True, env=merged, cwd=cwd or ROOT, timeout=120)


def test_shell_syntax() -> None:
    for script in (INSTALLER, ROOT / "run.sh"):
        result = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr


def test_unit_template_placeholders() -> None:
    body = UNIT.read_text()
    assert "@PREFIX@" in body
    assert "@ENV_FILE@" in body
    assert "@STATE_DIR@" in body
    assert "Environment=HOME=/root" in body
    assert "ProtectHome=read-only" in body
    assert "ReadWritePaths=@STATE_DIR@ /var/log/obhod /root/.goygram" in body
    assert "mkdir -p -m 700 /root/.goygram" in INSTALLER.read_text()
    assert "ExecStart=@PREFIX@/venv/bin/python -m BOT" in body
    assert "Restart=always" in body


def test_refuses_non_root() -> None:
    if os.geteuid() == 0:
        pytest.skip("running as root")
    result = run(["install"])
    assert result.returncode == 1
    assert "must run as root" in result.stderr
    assert "sudo bash" in result.stderr
    assert "nothing was changed" in result.stderr


def test_refuses_non_root_for_uninstall() -> None:
    if os.geteuid() == 0:
        pytest.skip("running as root")
    result = run(["uninstall"])
    assert result.returncode == 1
    assert "must run as root" in result.stderr


def test_unknown_argument() -> None:
    result = run(["--nope"])
    assert result.returncode == 2
    assert "unknown argument" in result.stderr


def test_help_text() -> None:
    result = run(["--help"])
    assert result.returncode == 0
    assert "usage: bash" in result.stdout
    assert "install" in result.stdout
    assert "--dev" in result.stdout


def test_dev_install_and_uninstall(tmp_path: Path) -> None:
    home = tmp_path / "home"
    payload = tmp_path / "payload"
    (payload / "Storage" / "remote").mkdir(parents=True)
    (payload / "BOT").mkdir(parents=True)
    (payload / "BOT" / "__init__.py").write_text("SENTINEL = 1\n")
    (payload / "requirements.txt").write_text("")
    shutil.copy(INSTALLER, payload / "Storage" / "obhod-install.sh")
    shutil.copy(UNIT, payload / "Storage" / "obhod.service")
    shutil.copy(ROOT / "Storage" / "remote" / "xray_agent.py", payload / "Storage" / "remote" / "xray_agent.py")
    env_conf = home / ".obhod" / "etc" / "obhod.env"
    env_conf.parent.mkdir(parents=True)
    env_conf.write_text(f"BOT_TOKEN=123456:ABC\nAPI_ID=42\nAPI_HASH={HASH}\nADMIN_ID=1000\n")
    env = {"HOME": str(home)}

    install = subprocess.run(
        ["bash", str(payload / "Storage" / "obhod-install.sh"), "install", "--dev", "--yes", "--skip-deps"],
        capture_output=True,
        text=True,
        env={**os.environ, **env},
        timeout=120,
    )
    assert install.returncode == 0, install.stderr
    assert "installed" in install.stdout
    prefix = home / ".obhod" / "app"
    assert (prefix / "BOT" / "__init__.py").is_file()
    assert (prefix / "Storage" / "remote" / "xray_agent.py").is_file()
    assert os.stat(env_conf).st_mode & 0o777 == 0o600
    assert os.stat(home / ".obhod" / "etc").st_mode & 0o777 == 0o700
    assert os.stat(home / ".obhod" / "state").st_mode & 0o777 == 0o700
    body = env_conf.read_text()
    assert "ADMIN_ID=1000" in body
    assert f"OBHOD_STATE_DIR={home}/.obhod/state" in body

    status = subprocess.run(
        ["bash", str(payload / "Storage" / "obhod-install.sh"), "status", "--dev"],
        capture_output=True,
        text=True,
        env={**os.environ, **env},
        timeout=60,
    )
    assert status.returncode == 0
    assert "config present" in status.stdout

    remove = subprocess.run(
        ["bash", str(payload / "Storage" / "obhod-install.sh"), "uninstall", "--dev"],
        capture_output=True,
        text=True,
        env={**os.environ, **env},
        timeout=60,
    )
    assert remove.returncode == 0
    assert not prefix.exists()
    assert env_conf.is_file()


def test_dev_install_rejects_bad_token(tmp_path: Path) -> None:
    home = tmp_path / "home"
    env_conf = home / ".obhod" / "etc" / "obhod.env"
    env_conf.parent.mkdir(parents=True)
    env_conf.write_text(f"BOT_TOKEN=broken\nAPI_ID=42\nAPI_HASH={HASH}\nADMIN_ID=1000\n")
    result = subprocess.run(
        ["bash", str(INSTALLER), "install", "--dev", "--yes", "--skip-deps"],
        capture_output=True,
        text=True,
        env={**os.environ, "HOME": str(home)},
        timeout=60,
    )
    assert result.returncode == 1
    assert "123456:ABC-DEF" in result.stderr


def test_dev_install_rejects_bad_api_hash(tmp_path: Path) -> None:
    home = tmp_path / "home"
    env_conf = home / ".obhod" / "etc" / "obhod.env"
    env_conf.parent.mkdir(parents=True)
    env_conf.write_text("BOT_TOKEN=1:A\nAPI_ID=42\nAPI_HASH=xyz\nADMIN_ID=1000\n")
    result = subprocess.run(
        ["bash", str(INSTALLER), "install", "--dev", "--yes", "--skip-deps"],
        capture_output=True,
        text=True,
        env={**os.environ, "HOME": str(home)},
        timeout=60,
    )
    assert result.returncode == 1
    assert "32 hex" in result.stderr


def dev_payload(tmp_path: Path) -> tuple[Path, dict[str, str], Path]:
    home = tmp_path / "home"
    payload = tmp_path / "payload"
    (payload / "Storage" / "remote").mkdir(parents=True)
    (payload / "BOT").mkdir(parents=True)
    (payload / "BOT" / "__init__.py").write_text("SENTINEL = 1\n")
    (payload / "requirements.txt").write_text("")
    shutil.copy(INSTALLER, payload / "Storage" / "obhod-install.sh")
    shutil.copy(UNIT, payload / "Storage" / "obhod.service")
    shutil.copy(ROOT / "Storage" / "remote" / "xray_agent.py", payload / "Storage" / "remote" / "xray_agent.py")
    env_conf = home / ".obhod" / "etc" / "obhod.env"
    env_conf.parent.mkdir(parents=True, exist_ok=True)
    env_conf.write_text(f"BOT_TOKEN=123456:ABC\nAPI_ID=42\nAPI_HASH={HASH}\nADMIN_ID=1000\n")
    return payload, {"HOME": str(home)}, env_conf


def dev_run(payload: Path, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(payload / "Storage" / "obhod-install.sh"), *args],
        capture_output=True,
        text=True,
        env={**os.environ, **env},
        timeout=120,
    )


def test_reinstall_wipes_prefix_and_keeps_credentials(tmp_path: Path) -> None:
    payload, env, env_conf = dev_payload(tmp_path)
    first = dev_run(payload, ["install", "--dev", "--yes", "--skip-deps"], env)
    assert first.returncode == 0, first.stderr
    prefix = Path(env["HOME"]) / ".obhod" / "app"
    marker = prefix / "leftover.txt"
    marker.write_text("old")
    state_dir = Path(env["HOME"]) / ".obhod" / "state"
    assert state_dir.is_dir()
    again = dev_run(payload, ["reinstall", "--dev", "--yes", "--skip-deps"], env)
    assert again.returncode == 0, again.stderr
    assert "reinstalling from scratch" in again.stdout
    assert "removed" in again.stdout
    assert not marker.exists()
    assert (prefix / "BOT" / "__init__.py").is_file()
    assert env_conf.is_file()


def test_reinstall_purge_all_forgets_credentials(tmp_path: Path) -> None:
    payload, env, env_conf = dev_payload(tmp_path)
    first = dev_run(payload, ["install", "--dev", "--yes", "--skip-deps"], env)
    assert first.returncode == 0, first.stderr
    state_dir = Path(env["HOME"]) / ".obhod" / "state"
    assert state_dir.is_dir()
    result = dev_run(payload, ["reinstall", "--dev", "--purge-all", "--skip-deps"], env)
    assert result.returncode == 1
    assert "bot token is required" in result.stderr
    assert not env_conf.exists()
    assert list(state_dir.iterdir()) == []
    assert not (Path(env["HOME"]) / ".obhod" / "app").exists()


def test_reinstall_help_text(tmp_path: Path) -> None:
    result = run(["--help"])
    assert "reinstall" in result.stdout
    assert "--purge-all" in result.stdout


def test_reinstall_refuses_non_root() -> None:
    if os.geteuid() == 0:
        pytest.skip("running as root")
    result = run(["reinstall"])
    assert result.returncode == 1
    assert "must run as root" in result.stderr


def test_reinstall_stops_leftover_processes(tmp_path: Path) -> None:
    payload, env, _ = dev_payload(tmp_path)
    prefix = Path(env["HOME"]) / ".obhod" / "app"
    (prefix / "venv" / "bin").mkdir(parents=True)
    script = prefix / "venv" / "bin" / "python"
    script.write_text("#!/bin/bash\nsleep 300\n")
    script.chmod(0o755)
    proc = subprocess.Popen([str(script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        result = dev_run(payload, ["reinstall", "--dev", "--yes", "--skip-deps"], env)
        assert result.returncode == 0, result.stderr
        assert "leftover processes stopped" in result.stdout
        assert proc.wait(timeout=15) is not None
    finally:
        if proc.poll() is None:
            proc.kill()
