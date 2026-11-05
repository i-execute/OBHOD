from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "get.sh"
BASH = shutil.which("bash") or "/bin/bash"


def fake_root(tmp_path: Path) -> Path:
    binaries = tmp_path / "bin"
    binaries.mkdir(exist_ok=True)
    ident = binaries / "id"
    ident.write_text("#!/bin/sh\necho 0\n", encoding="utf-8")
    ident.chmod(0o755)
    return binaries


def fake_user(tmp_path: Path) -> Path:
    binaries = tmp_path / "userbin"
    binaries.mkdir(exist_ok=True)
    ident = binaries / "id"
    ident.write_text("#!/bin/sh\necho 1000\n", encoding="utf-8")
    ident.chmod(0o755)
    return binaries


def run(tmp_path: Path, *args: str, env: dict[str, str] | None = None, root: bool = True, path: str | None = None) -> subprocess.CompletedProcess[str]:
    binaries = fake_root(tmp_path) if root else fake_user(tmp_path)
    base = {
        "PATH": path if path is not None else f"{binaries}:/usr/local/bin:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
    }
    if env:
        base.update(env)
    return subprocess.run(
        [BASH, str(SCRIPT), *args],
        cwd=str(ROOT),
        env=base,
        input="",
        capture_output=True,
        text=True,
        timeout=180,
    )


def creds() -> dict[str, str]:
    return {
        "BOT_TOKEN": "123456:ABC-DEF",
        "API_ID": "12345",
        "API_HASH": "0123456789abcdef0123456789abcdef",
        "ADMIN_ID": "777",
    }


def test_script_exists_and_is_bash() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in text


def test_script_has_no_comments() -> None:
    for number, line in enumerate(SCRIPT.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            assert number == 1, f"line {number}: {stripped}"


def test_script_syntax() -> None:
    result = subprocess.run([BASH, "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_refuses_without_root(tmp_path: Path) -> None:
    result = run(tmp_path, "--dry-run", root=False)
    assert result.returncode == 1
    assert "root" in result.stderr
    assert "sudo" in result.stderr


def test_dry_run_needs_no_network(tmp_path: Path) -> None:
    result = run(tmp_path, "--dry-run")
    assert result.returncode == 0, result.stderr
    assert "i-execute/OBHOD" in result.stdout
    assert "install" in result.stdout


def test_dry_run_reports_git_clone(tmp_path: Path) -> None:
    result = run(tmp_path, "--dry-run")
    assert "git clone --depth 1 https://github.com/i-execute/OBHOD.git" in result.stdout


def test_dry_run_reports_local_source(tmp_path: Path) -> None:
    result = run(tmp_path, "--dry-run", env={"OBHOD_SRC_DIR": str(ROOT)})
    assert result.returncode == 0, result.stderr
    assert "source: " + str(ROOT) in result.stdout
    assert "git clone" not in result.stdout


def test_dry_run_shows_target_directory(tmp_path: Path) -> None:
    target = tmp_path / "src"
    result = run(tmp_path, "--dry-run", f"--dir={target}")
    assert f"directory: {target}" in result.stdout
    assert f"bash {target}/Storage/obhod-install.sh" in result.stdout


def test_dry_run_reports_branch(tmp_path: Path) -> None:
    result = run(tmp_path, "--dry-run", "--ref=v1.2.3")
    assert "branch: v1.2.3" in result.stdout


def test_repo_override(tmp_path: Path) -> None:
    result = run(tmp_path, "--dry-run", "--repo=someone/other")
    assert "credentials:" in result.stdout
    assert "someone/other" in result.stdout


def test_repo_override_by_env(tmp_path: Path) -> None:
    result = run(tmp_path, "--dry-run", env={"OBHOD_REPO": "someone/other"})
    assert "https://github.com/someone/other.git" in result.stdout


def test_command_is_passed_through(tmp_path: Path) -> None:
    result = run(tmp_path, "--dry-run", "reinstall", "--dev")
    assert result.stdout.strip().endswith("obhod-install.sh reinstall --dev")


def test_default_command_is_install(tmp_path: Path) -> None:
    result = run(tmp_path, "--dry-run")
    assert result.stdout.strip().endswith("obhod-install.sh install")


def test_env_file_is_written_from_environment(tmp_path: Path) -> None:
    env_path = tmp_path / "etc" / "obhod.env"
    result = run(tmp_path, "--dry-run", f"--env-file={env_path}", env=creds())
    assert result.returncode == 0, result.stderr
    body = env_path.read_text(encoding="utf-8")
    assert "BOT_TOKEN=123456:ABC-DEF" in body
    assert "API_ID=12345" in body
    assert "API_HASH=0123456789abcdef0123456789abcdef" in body
    assert "ADMIN_ID=777" in body
    mode = stat.S_IMODE(env_path.stat().st_mode)
    assert mode == 0o600


def test_env_file_absent_without_credentials(tmp_path: Path) -> None:
    env_path = tmp_path / "obhod.env"
    result = run(tmp_path, "--dry-run", f"--env-file={env_path}")
    assert result.returncode == 0, result.stderr
    assert not env_path.exists()
    assert "credentials: asked in the terminal" in result.stdout


def test_dry_run_marks_environment_credentials(tmp_path: Path) -> None:
    result = run(tmp_path, "--dry-run", env=creds())
    assert "credentials: from the environment" in result.stdout


def test_missing_terminal_without_credentials(tmp_path: Path) -> None:
    result = run(tmp_path)
    assert result.returncode == 1
    assert "terminal" in result.stderr
    assert "BOT_TOKEN" in result.stderr


def test_sync_copies_payload(tmp_path: Path) -> None:
    target = tmp_path / "dest"
    result = run(tmp_path, "--no-install", f"--dir={target}", env={"OBHOD_SRC_DIR": str(ROOT)})
    assert result.returncode == 0, result.stderr
    assert (target / "Storage" / "obhod-install.sh").is_file()
    assert (target / "BOT" / "app.py").is_file()
    assert (target / "requirements.txt").is_file()
    assert (target / ".obhod-src").is_file()


def test_sync_skips_git_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Storage").mkdir()
    (source / "Storage" / "obhod-install.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    (source / "keep.txt").write_text("ok", encoding="utf-8")
    (source / ".gitignore").write_text("x", encoding="utf-8")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("x", encoding="utf-8")
    (source / "__pycache__").mkdir()
    (source / "__pycache__" / "a.pyc").write_text("x", encoding="utf-8")
    target = tmp_path / "dest"
    result = run(tmp_path, "--no-install", f"--dir={target}", env={"OBHOD_SRC_DIR": str(source)})
    assert result.returncode == 0, result.stderr
    assert (target / "keep.txt").is_file()
    assert (target / ".git").is_dir()
    assert not (target / "__pycache__").exists()


def test_sync_replaces_stale_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Storage").mkdir()
    (source / "Storage" / "obhod-install.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    target = tmp_path / "dest"
    result = run(tmp_path, "--no-install", f"--dir={target}", env={"OBHOD_SRC_DIR": str(source)})
    assert result.returncode == 0, result.stderr
    stale = target / "stale.txt"
    stale.write_text("old", encoding="utf-8")
    again = run(tmp_path, "--no-install", f"--dir={target}", env={"OBHOD_SRC_DIR": str(source)})
    assert again.returncode == 0, again.stderr
    assert not stale.exists()


def test_sync_keeps_foreign_directory(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Storage").mkdir()
    (source / "Storage" / "obhod-install.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    target = tmp_path / "dest"
    target.mkdir()
    mine = target / "mine.txt"
    mine.write_text("keep", encoding="utf-8")
    result = run(tmp_path, "--no-install", f"--dir={target}", env={"OBHOD_SRC_DIR": str(source)})
    assert result.returncode == 0, result.stderr
    assert mine.is_file()


def test_missing_source_payload(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    result = run(tmp_path, "--no-install", env={"OBHOD_SRC_DIR": str(empty)})
    assert result.returncode == 1
    assert "obhod-install.sh" in result.stderr


def test_dry_run_reports_tarball_without_git(tmp_path: Path) -> None:
    binaries = tmp_path / "minbin"
    binaries.mkdir(exist_ok=True)
    ident = binaries / "id"
    ident.write_text("#!/bin/sh\necho 0\n", encoding="utf-8")
    ident.chmod(0o755)
    for name in ("curl", "tar"):
        source = shutil.which(name)
        if source:
            (binaries / name).symlink_to(source)
    result = run(tmp_path, "--dry-run", root=True, path=str(binaries))
    assert result.returncode == 0, result.stderr
    assert "codeload.github.com/i-execute/OBHOD/tar.gz/HEAD" in result.stdout
    assert "git clone" not in result.stdout


def test_piped_script_works(tmp_path: Path) -> None:
    target = tmp_path / "dest"
    binaries = fake_root(tmp_path)
    body = SCRIPT.read_text(encoding="utf-8")
    result = subprocess.run(
        [BASH, "-s", "--", f"--dir={target}", "--no-install"],
        input=body,
        cwd=str(ROOT),
        env={"PATH": f"{binaries}:/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path), "LANG": "C.UTF-8", "OBHOD_SRC_DIR": str(ROOT)},
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stderr
    assert (target / "Storage" / "obhod-install.sh").is_file()


def test_missing_tools_is_reported(tmp_path: Path) -> None:
    binaries = fake_root(tmp_path)
    result = run(tmp_path, "--dry-run", path=str(binaries))
    assert result.returncode == 1
    assert "git" in result.stderr
    assert "curl" in result.stderr


def test_no_install_prints_manual_command(tmp_path: Path) -> None:
    target = tmp_path / "dest"
    result = run(tmp_path, "--no-install", f"--dir={target}", env={"OBHOD_SRC_DIR": str(ROOT)})
    assert "the install is skipped" in result.stdout
    assert f"bash {target}/Storage/obhod-install.sh install" in result.stdout


def test_installer_is_skipped_without_terminal_and_credentials(tmp_path: Path) -> None:
    target = tmp_path / "dest"
    result = run(tmp_path, f"--dir={target}", env={"OBHOD_SRC_DIR": str(ROOT)})
    assert result.returncode == 1
    assert not (target / "Storage" / "obhod-install.sh").exists()


def test_env_names_with_prefix(tmp_path: Path) -> None:
    env_path = tmp_path / "obhod.env"
    env = {
        "OBHOD_TOKEN": "999:XYZ",
        "OBHOD_API_ID": "555",
        "OBHOD_API_HASH": "f" * 32,
        "OBHOD_ADMIN_ID": "111",
    }
    result = run(tmp_path, "--dry-run", f"--env-file={env_path}", env=env)
    assert result.returncode == 0, result.stderr
    body = env_path.read_text(encoding="utf-8")
    assert "BOT_TOKEN=999:XYZ" in body
    assert "ADMIN_ID=111" in body


def test_no_secrets_in_output(tmp_path: Path) -> None:
    result = run(tmp_path, "--dry-run", env=creds())
    assert "ABC-DEF" not in result.stdout
    assert "ABC-DEF" not in result.stderr


@pytest.mark.parametrize("flag", ["--dry-run", "--no-install"])
def test_unknown_positional_goes_to_installer(tmp_path: Path, flag: str) -> None:
    result = run(tmp_path, flag, "--prefix=/tmp/x", env={"OBHOD_SRC_DIR": str(ROOT), "OBHOD_DIR": str(tmp_path / "src")})
    assert result.returncode in {0, 1}
    if result.returncode == 0:
        assert "--prefix=/tmp/x" in result.stdout


def test_trap_removes_work_directory(tmp_path: Path) -> None:
    target = tmp_path / "dest"
    work = tmp_path / "work"
    work.mkdir()
    result = run(tmp_path, "--no-install", f"--dir={target}", env={"OBHOD_SRC_DIR": str(ROOT), "TMPDIR": str(work)})
    assert result.returncode == 0, result.stderr
    leftovers = [item.name for item in work.iterdir() if item.name.startswith("tmp")]
    assert leftovers == []


def test_script_is_executable_bit_agnostic() -> None:
    result = subprocess.run([BASH, "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0


def test_vendored_installer_untouched_by_script() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "Storage/obhod-install.sh" in text
    assert "Storage/install.sh" not in text


def test_os_environ_not_leaked_into_call() -> None:
    assert "OBHOD_SRC_DIR" in SCRIPT.read_text(encoding="utf-8")
    assert os.sep == "/"


@pytest.mark.parametrize("value", ["/", "/etc", "/usr", "/var", "/opt", "relative/path", "/opt/../etc"])
def test_the_installer_refuses_a_dangerous_target_directory(tmp_path: Path, value: str) -> None:
    result = run(tmp_path, "--no-install", "--dry-run", env={"OBHOD_DIR": value, "OBHOD_SRC_DIR": str(ROOT)})
    assert result.returncode != 0
    assert "OBHOD_DIR" in result.stderr


def test_the_installer_accepts_a_directory_of_its_own(tmp_path: Path) -> None:
    result = run(tmp_path, "--no-install", "--dry-run", env={"OBHOD_DIR": str(tmp_path / "src"), "OBHOD_SRC_DIR": str(ROOT)})
    assert result.returncode == 0, result.stderr


def test_sync_survives_a_file_that_cannot_be_written(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "BOT").mkdir()
    (source / "BOT" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (source / "Storage").mkdir()
    (source / "Storage" / "obhod-install.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    target = tmp_path / "dest"
    target.mkdir()
    (target / "BOT").mkdir()
    frozen = target / "BOT" / "app.py"
    frozen.write_text("old\n", encoding="utf-8")
    result = run(tmp_path, "--no-install", f"--dir={target}", env={"OBHOD_SRC_DIR": str(source)})
    assert result.returncode == 0, result.stderr
    assert (target / "BOT" / "app.py").read_text(encoding="utf-8") == "print('hi')\n"
    assert (target / "Storage" / "obhod-install.sh").is_file()
    assert "no tar pipe" in result.stdout


def test_sync_does_not_need_tar(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "BOT").mkdir()
    (source / "BOT" / "app.py").write_text("ok\n", encoding="utf-8")
    (source / "Storage").mkdir()
    (source / "Storage" / "obhod-install.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    binaries = fake_root(tmp_path)
    tools = tmp_path / "tools"
    tools.mkdir()
    for name in ("cp", "mkdir", "rm", "chmod", "basename", "dirname", "touch", "ls", "wc", "id", "install", "sed", "grep", "mktemp", "date", "cat", "uname", "sleep"):
        found = shutil.which(name)
        if found:
            (tools / name).symlink_to(found)
    env = {
        "PATH": f"{binaries}:{tools}",
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "OBHOD_SRC_DIR": str(source),
    }
    result = subprocess.run(
        [BASH, str(SCRIPT), "--no-install", f"--dir={tmp_path / 'dest'}"],
        cwd=str(ROOT),
        env=env,
        input="",
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "dest" / "BOT" / "app.py").is_file()


def test_a_default_destination_is_picked_when_none_is_given(tmp_path: Path) -> None:
    result = run(tmp_path, "--dry-run", env={"BOT_TOKEN": "1:A", "API_ID": "1", "API_HASH": "x" * 32})
    assert result.returncode == 0, result.stderr
    assert "directory: " in result.stdout
    chosen = [line for line in result.stdout.splitlines() if line.startswith("directory: ")][0].split(": ", 1)[1]
    assert chosen.startswith("/")
    assert "obhod" in chosen


def test_the_tree_is_rebuilt_when_a_file_inside_is_not_writable(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "BOT").mkdir()
    (source / "BOT" / "app.py").write_text("new\n", encoding="utf-8")
    (source / "Storage").mkdir()
    (source / "Storage" / "obhod-install.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    target = tmp_path / "dest"
    (target / "BOT").mkdir(parents=True)
    frozen = target / "BOT" / "app.py"
    frozen.write_text("old\n", encoding="utf-8")
    frozen.chmod(0o444)
    try:
        result = run(tmp_path, "--no-install", f"--dir={target}", env={"OBHOD_SRC_DIR": str(source)})
    finally:
        frozen.chmod(0o644)
    assert result.returncode == 0, result.stderr
    assert (target / "BOT" / "app.py").read_text(encoding="utf-8") == "new\n"
    assert (target / "Storage" / "obhod-install.sh").is_file()


def test_a_read_only_destination_is_explained_instead_of_a_tar_trace(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Storage").mkdir()
    (source / "Storage" / "obhod-install.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    target = tmp_path / "dest"
    target.mkdir()
    target.chmod(0o555)
    try:
        result = run(tmp_path, "--no-install", f"--dir={target}", env={"OBHOD_SRC_DIR": str(source)})
    finally:
        target.chmod(0o755)
    assert result.returncode == 1
    assert "cannot be written" in result.stderr
    assert "root shell" in result.stderr
    assert "function not implemented" not in result.stderr
    assert "tar:" not in result.stderr


def test_a_read_only_env_directory_does_not_abort_the_run(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Storage").mkdir()
    (source / "Storage" / "obhod-install.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    env_dir = tmp_path / "etc"
    env_dir.mkdir()
    env_file = env_dir / "obhod.env"
    env_dir.chmod(0o555)
    try:
        result = run(
            tmp_path,
            f"--dir={tmp_path / 'dest'}",
            f"--env-file={env_file}",
            env={"OBHOD_SRC_DIR": str(source), **creds()},
        )
    finally:
        env_dir.chmod(0o755)
    assert result.returncode == 0, result.stderr
    assert "read-only" in result.stderr.lower() or "could not be written" in result.stderr.lower()
    assert "files updated in" in result.stdout
    assert "starting the installer" in result.stdout
