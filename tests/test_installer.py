from __future__ import annotations

import os
import pty
import re
import select
import shlex
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "Storage" / "obhod_install.sh"
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
    assert "ReadWritePaths=@STATE_DIR@ /var/log /root/.goygram -/etc/fail2ban -/etc/ssh" in body
    assert "-/var/lib/xray-manager -/root/.ssh -/home -/opt" in body
    assert "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK" in body
    assert "mkdir -p -m 700 /root/.goygram /root/.ssh" in INSTALLER.read_text()
    assert "mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d /etc/fail2ban/action.d" in INSTALLER.read_text()
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
    shutil.copy(INSTALLER, payload / "Storage" / "obhod_install.sh")
    shutil.copy(UNIT, payload / "Storage" / "obhod.service")
    shutil.copy(ROOT / "Storage" / "remote" / "xray_agent.py", payload / "Storage" / "remote" / "xray_agent.py")
    env_conf = home / ".obhod" / "etc" / "obhod.env"
    env_conf.parent.mkdir(parents=True)
    env_conf.write_text(f"BOT_TOKEN=123456:ABC\nAPI_ID=42\nAPI_HASH={HASH}\nADMIN_ID=1000\n")
    env = {"HOME": str(home)}

    install = subprocess.run(
        ["bash", str(payload / "Storage" / "obhod_install.sh"), "install", "--dev", "--yes", "--skip-deps"],
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
    assert os.stat(home / ".obhod" / "etc").st_mode & 0o777 == env_conf.parent.stat().st_mode & 0o777
    assert os.stat(home / ".obhod" / "state").st_mode & 0o777 == 0o700
    body = env_conf.read_text()
    assert "ADMIN_ID=1000" in body
    assert f"OBHOD_STATE_DIR={home}/.obhod/state" in body

    status = subprocess.run(
        ["bash", str(payload / "Storage" / "obhod_install.sh"), "status", "--dev"],
        capture_output=True,
        text=True,
        env={**os.environ, **env},
        timeout=60,
    )
    assert status.returncode == 0
    assert "config present" in status.stdout

    remove = subprocess.run(
        ["bash", str(payload / "Storage" / "obhod_install.sh"), "uninstall", "--dev"],
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
    shutil.copy(INSTALLER, payload / "Storage" / "obhod_install.sh")
    shutil.copy(UNIT, payload / "Storage" / "obhod.service")
    shutil.copy(ROOT / "Storage" / "remote" / "xray_agent.py", payload / "Storage" / "remote" / "xray_agent.py")
    env_conf = home / ".obhod" / "etc" / "obhod.env"
    env_conf.parent.mkdir(parents=True, exist_ok=True)
    env_conf.write_text(f"BOT_TOKEN=123456:ABC\nAPI_ID=42\nAPI_HASH={HASH}\nADMIN_ID=1000\n")
    return payload, {"HOME": str(home)}, env_conf


def dev_run(payload: Path, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(payload / "Storage" / "obhod_install.sh"), *args],
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
    assert "no terminal to read the credentials" in result.stderr
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

def test_credentials_are_read_from_the_terminal_not_from_a_pipe(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    script = INSTALLER.read_text(encoding="utf-8")
    assert "read -r value </dev/tty" in script
    assert "tty_present()" in script

    pid, fd = pty.fork()
    if pid == 0:
        os.environ["HOME"] = str(home)
        os.execvp(
            "bash",
            ["bash", "-c", "bash %s install --dev --skip-deps < /dev/null" % shlex.quote(str(INSTALLER))],
        )
    answers = ["123456:ABC-DEF", "42", HASH, "1000"]
    seen = ""
    deadline = time.time() + 60
    try:
        while time.time() < deadline and answers:
            ready, _, _ = select.select([fd], [], [], 0.5)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 4096).decode("utf-8", "replace")
            except OSError:
                break
            if not chunk:
                break
            seen += chunk
            if chunk.rstrip().endswith(":"):
                os.write(fd, (answers.pop(0) + "\n").encode())
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.5)
            if not ready:
                done, _status = os.waitpid(pid, os.WNOHANG)
                if done:
                    break
                continue
            try:
                chunk = os.read(fd, 4096).decode("utf-8", "replace")
            except OSError:
                break
            if not chunk:
                break
            seen += chunk
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
    assert not answers, seen
    assert "telegram bot token" in seen
    assert "installed" in seen


def test_a_run_without_any_terminal_stops_before_it_hangs(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    result = subprocess.run(
        ["bash", str(INSTALLER), "install", "--dev", "--skip-deps"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env={**os.environ, "HOME": str(home)},
        start_new_session=True,
        timeout=60,
    )
    assert result.returncode == 1
    assert "no terminal to read the credentials" in result.stderr

def test_a_second_install_replaces_everything_without_breaking(tmp_path: Path) -> None:
    payload, env, env_conf = dev_payload(tmp_path)
    first = dev_run(payload, ["install", "--dev", "--yes", "--skip-deps"], env)
    assert first.returncode == 0, first.stderr
    prefix = Path(env["HOME"]) / ".obhod" / "app"
    assert (prefix / "BOT" / "__init__.py").read_text() == "SENTINEL = 1\n"

    (prefix / "BOT" / "stale.py").write_text("OLD = 1\n")
    (prefix / "Storage" / "remote" / "old_agent.py").write_text("OLD = 1\n")
    (payload / "BOT" / "__init__.py").write_text("SENTINEL = 2\n")
    (payload / "BOT" / "fresh.py").write_text("NEW = 1\n")

    second = dev_run(payload, ["install", "--dev", "--yes", "--skip-deps"], env)
    assert second.returncode == 0, second.stderr
    assert "previous install" in second.stdout
    assert "installed over the previous install" in second.stdout
    assert (prefix / "BOT" / "__init__.py").read_text() == "SENTINEL = 2\n"
    assert (prefix / "BOT" / "fresh.py").is_file()
    assert not (prefix / "BOT" / "stale.py").exists()
    assert not (prefix / "Storage" / "remote" / "old_agent.py").exists()
    assert (prefix / "Storage" / "remote" / "xray_agent.py").is_file()
    body = env_conf.read_text()
    assert "BOT_TOKEN=123456:ABC" in body
    assert "ADMIN_ID=1000" in body
    state_dir = Path(env["HOME"]) / ".obhod" / "state"
    assert state_dir.is_dir()

    third = dev_run(payload, ["install", "--dev", "--yes", "--skip-deps"], env)
    assert third.returncode == 0, third.stderr
    assert "installed over the previous install" in third.stdout

def test_a_broken_virtual_environment_is_rebuilt(tmp_path: Path) -> None:
    script = INSTALLER.read_text(encoding="utf-8")
    assert "the virtual environment is broken, recreating it" in script
    assert 'rm -rf "$PREFIX/venv"' in script

def test_the_plain_output_has_no_escape_codes(tmp_path: Path) -> None:
    payload, env, env_conf = dev_payload(tmp_path)
    result = dev_run(payload, ["install", "--dev", "--yes", "--skip-deps"], env)
    assert result.returncode == 0, result.stderr
    assert "\033[" not in result.stdout
    assert "OBHOD" in result.stdout
    steps = re.findall(r"\[(\d+)/(\d+)\]", result.stdout)
    assert steps
    total = steps[0][1]
    assert [int(number) for number, _ in steps] == list(range(1, len(steps) + 1))
    assert {size for _, size in steps} == {total}
    assert "[1/%s]" % total in result.stdout
    assert "done" in result.stdout
    assert "telegram control bot" in result.stdout


def test_the_token_and_the_hash_are_not_echoed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["HOME"] = str(home)
        os.execvp(
            "bash",
            ["bash", "-c", "bash %s install --dev --skip-deps < /dev/null" % shlex.quote(str(INSTALLER))],
        )
    answers = ["123456:ABC-DEF", "42", HASH, "1000"]
    seen = ""
    deadline = time.time() + 60
    try:
        while time.time() < deadline and answers:
            ready, _, _ = select.select([fd], [], [], 0.5)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 4096).decode("utf-8", "replace")
            except OSError:
                break
            seen += chunk
            if chunk.rstrip().endswith(":"):
                if "hidden" in chunk:
                    time.sleep(0.1)
                os.write(fd, (answers.pop(0) + "\n").encode())
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.5)
            if not ready:
                done, _status = os.waitpid(pid, os.WNOHANG)
                if done:
                    break
                continue
            try:
                chunk = os.read(fd, 4096).decode("utf-8", "replace")
            except OSError:
                break
            if not chunk:
                break
            seen += chunk
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
    assert "hidden" in seen
    assert HASH not in seen
    assert "ABC-DEF" not in seen


def test_the_installer_picks_another_port_when_one_is_busy(tmp_path: Path) -> None:
    text = INSTALLER.read_text(encoding="utf-8")
    assert "port_listening()" in text
    assert "pick_port()" in text
    assert "resolve_ports" in text
    assert "OBHOD_SUB_PORT=" in text
    assert "OBHOD_API_PORT=" in text


def test_the_installer_never_kills_a_foreign_service(tmp_path: Path) -> None:
    text = INSTALLER.read_text(encoding="utf-8")
    for word in ("kill -9", "fuser -k", "pkill -f", "killall"):
        assert word not in text
    assert "left alone" in text
    assert "nothing is stopped or killed" in text


def test_a_foreign_config_directory_keeps_its_mode(tmp_path: Path) -> None:
    payload, env, env_conf = dev_payload(tmp_path)
    env_conf.parent.mkdir(parents=True, exist_ok=True)
    env_conf.parent.chmod(0o755)
    env_conf.write_text("BOT_TOKEN=123456:ABC\nAPI_ID=42\nAPI_HASH=%s\nADMIN_ID=1000\n" % HASH, encoding="utf-8")
    result = dev_run(payload, ["install", "--dev", "--yes", "--skip-deps"], env)
    assert result.returncode == 0, result.stderr
    assert env_conf.parent.stat().st_mode & 0o777 == 0o755
    assert env_conf.stat().st_mode & 0o777 == 0o600
    assert "the config file itself is 0600" in result.stdout


def test_the_installer_never_chmods_a_shared_directory(tmp_path: Path) -> None:
    script = INSTALLER.read_text(encoding="utf-8")
    assert "ensure_private_dir" in script
    assert 'chmod 700 "$CONF_DIR"' not in script
    assert 'chmod 700 "$STATE_DIR"' not in script
    assert 'chmod 700 "${LOG_DIR:-/var/log/obhod}"' not in script
    shared = ("/tmp", "/var", "/etc", "/usr", "/home", "/root", "/opt", "/")
    body = script.split("ensure_private_dir() {", 1)[1].split("\n}", 1)[0]
    for path in shared:
        assert path in body


def test_the_unit_carries_the_product_name() -> None:
    unit = (INSTALLER.parent / "obhod.service").read_text(encoding="utf-8")
    assert "Description=OBHOD telegram control bot" in unit
    assert "FreeTurn control bot" not in unit
    assert "ExecStart=@PREFIX@/venv/bin/python -m BOT" in unit


def test_the_paste_harvest_disables_echo_before_the_clone() -> None:
    script = (ROOT / "get.sh").read_text(encoding="utf-8")
    assert "echo_off()" in script
    assert "echo_on()" in script
    assert "detach_stdin()" in script
    assert "mask_token" in script and "mask_hash" in script
    body = script.split("echo_off\nfetch_source", 1)
    assert len(body) == 2
    assert "trap 'echo_on; cleanup' EXIT" in script
    assert "/dev/null" in script
    assert "existing config at" in script


def test_the_installer_echoes_nothing_while_the_credentials_are_typed() -> None:
    script = INSTALLER.read_text(encoding="utf-8")
    block = script.split("existing config at $ENV_FILE", 1)[1].split("loud_tty", 1)[0] if "existing config at $ENV_FILE" in script else script.split("quiet_tty", 1)[1]
    assert "read_value 'telegram bot token: '" in block
    assert "read_value 'telegram api_hash: '" in block
    assert script.count("quiet_tty") >= 1
    assert "mask_token" in script and "mask_hash" in script
    assert "token: $(mask_token" in script


def test_pip_is_bounded_and_never_silent_by_default() -> None:
    script = INSTALLER.read_text(encoding="utf-8")
    assert "--timeout 20 --retries 2" in script
    assert '"--progress-bar" "off"' in script
    assert 'if [ -t 1 ]; then' in script
    assert "quiet=()" in script
    assert "check_index" in script
    assert "PIP_INDEX_URL" in script
    assert "is not reachable from this server" in script


def test_the_unit_starts_the_interpreter_that_actually_exists(tmp_path: Path) -> None:
    venv_prefix = tmp_path / "with-venv"
    (venv_prefix / "venv" / "bin").mkdir(parents=True)
    fake = venv_prefix / "venv" / "bin" / "python"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    bare_prefix = tmp_path / "no-venv"
    bare_prefix.mkdir()
    out_venv = tmp_path / "venv.service"
    out_bare = tmp_path / "bare.service"
    script = (
        "source {installer}\n"
        "ui_init\n"
        "ENV_FILE=/etc/obhod/obhod.env\n"
        "STATE_DIR=/var/lib/obhod\n"
        "SKIP_DEPS=1\n"
        "PREFIX={venv}\nrender_unit {out_venv}\n"
        "PREFIX={bare}\nrender_unit {out_bare}\n"
    ).format(
        installer=shlex.quote(str(INSTALLER)),
        venv=shlex.quote(str(venv_prefix)),
        bare=shlex.quote(str(bare_prefix)),
        out_venv=shlex.quote(str(out_venv)),
        out_bare=shlex.quote(str(out_bare)),
    )
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        env={**os.environ, "OBHOD_LIB": "1"},
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "ExecStart=%s -m BOT" % fake in out_venv.read_text(encoding="utf-8")
    bare_unit = out_bare.read_text(encoding="utf-8")
    system_python = shutil.which("python3")
    assert system_python
    assert "ExecStart=%s -m BOT" % system_python in bare_unit
    assert "venv/bin/python" not in bare_unit


def test_without_a_runtime_the_unit_keeps_the_venv_path() -> None:
    script = (
        "source {installer}\n"
        "ui_init\n"
        "ENV_FILE=/etc/obhod/obhod.env\n"
        "STATE_DIR=/var/lib/obhod\n"
        "SKIP_DEPS=0\n"
        "PYTHON_BIN=python3\n"
        "PREFIX=/nonexistent-prefix\n"
        "unit_runtime\n"
    ).format(installer=shlex.quote(str(INSTALLER)))
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        env={**os.environ, "OBHOD_LIB": "1"},
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "/nonexistent-prefix/venv/bin/python"


def test_cmd_update_copies_full_storage_heals_corrupt_state_and_reports_both_cores(tmp_path: Path) -> None:
    payload, env, env_conf = dev_payload(tmp_path)
    shutil.copy2(ROOT / "Storage" / "obhod_setup.py", payload / "Storage" / "obhod_setup.py")
    env_conf.parent.mkdir(parents=True, exist_ok=True)
    env_conf.write_text("BOT_TOKEN=123456:ABC\nAPI_ID=42\nAPI_HASH=%s\nADMIN_ID=1000\nOBHOD_SUB_PORT=2096\nOBHOD_API_PORT=62789\n" % HASH, encoding="utf-8")
    state_dir = Path(env["HOME"]) / ".obhod" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "state.json").write_text("{broken-json", encoding="utf-8")
    (state_dir / ".state-stale.json").write_text("tmp", encoding="utf-8")
    res = dev_run(payload, ["update", "--dev", "--skip-deps"], env)
    assert res.returncode == 0, res.stderr
    assert "updated" in res.stdout
    assert "xray-core & freeturn" in res.stdout
    prefix = Path(env["HOME"]) / ".obhod" / "app"
    assert (prefix / "Storage" / "obhod_setup.py").is_file()
    assert not (state_dir / ".state-stale.json").exists()
    assert not (state_dir / "state.json").exists()
    assert list(state_dir.glob("state.json.corrupt.*"))
    status_res = dev_run(payload, ["status", "--dev"], env)
    assert status_res.returncode == 0
    assert "xray-core:" in status_res.stdout
    assert "freeturn:" in status_res.stdout
    cli_bin = Path(env["HOME"]) / ".obhod" / "bin" / "obhod"
    assert cli_bin.is_file()
    cli_flag_res = subprocess.run([str(cli_bin), "--bad-flag"], capture_output=True, text=True, env=env, timeout=30)
    assert cli_flag_res.returncode == 2
    assert "command-line flags are not supported" in cli_flag_res.stdout
    nuke_res = dev_run(payload, ["nuke", "--dev"], env)
    assert nuke_res.returncode == 0, nuke_res.stderr
    assert "wiped everything in dev mode" in nuke_res.stdout
    assert not prefix.exists()
    assert not env_conf.exists()
    assert not state_dir.exists()
    assert not cli_bin.exists()

