from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "obhod_watchdog.py"
BASELINE = ROOT / "tools" / "obhod_protection.baseline.json"


def load_tool() -> object:
    spec = importlib.util.spec_from_file_location("obhod_watchdog", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def clone(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    shutil.copytree(
        ROOT,
        target,
        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", ".git", "*.pyc"),
    )
    return target


def run_tool(target: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(target / "tools" / "obhod_watchdog.py"), *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_the_shipped_tree_has_no_policy_violation() -> None:
    tool = load_tool()
    assert tool.policy_report() == {}


def test_the_baseline_is_sealed_and_matches_the_tree() -> None:
    tool = load_tool()
    body = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert body["version"] == 1
    assert set(body["files"]) == set(tool.PROTECTED)
    assert tool.verify() == []


def test_the_baseline_covers_every_file_it_claims() -> None:
    body = json.loads(BASELINE.read_text(encoding="utf-8"))
    for name, value in body["files"].items():
        assert (ROOT / name).is_file(), name
        assert len(value) == 64
        assert value == value.lower()


def test_a_touched_protected_file_is_reported(tmp_path: Path) -> None:
    target = clone(tmp_path)
    guard = target / "BOT" / "guard.py"
    guard.write_text(guard.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    result = run_tool(target, "verify")
    assert result.returncode == 1
    assert "BOT/guard.py changed" in result.stdout


def test_a_removed_protection_is_reported_even_after_resealing(tmp_path: Path) -> None:
    target = clone(tmp_path)
    server = target / "Storage" / "remote" / "sub_server.py"
    server.write_text(
        server.read_text(encoding="utf-8").replace("hmac.compare_digest", "operator.eq"),
        encoding="utf-8",
    )
    run_tool(target, "seal")
    result = run_tool(target, "verify")
    assert result.returncode == 1
    assert "constant time" in result.stdout


def test_a_dropped_owner_gate_is_reported(tmp_path: Path) -> None:
    target = clone(tmp_path)
    app = target / "BOT" / "app.py"
    app.write_text(app.read_text(encoding="utf-8").replace("who == self.admin_id", "True"), encoding="utf-8")
    run_tool(target, "seal")
    result = run_tool(target, "verify")
    assert result.returncode == 1
    assert "owner" in result.stdout.lower()


def test_a_shell_call_is_reported(tmp_path: Path) -> None:
    target = clone(tmp_path)
    app = target / "BOT" / "app.py"
    app.write_text(
        app.read_text(encoding="utf-8") + "\n\ndef _escape(command):\n    return subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    result = run_tool(target, "policy")
    assert result.returncode == 1
    assert "shell=True" in result.stdout


def test_a_firewall_policy_change_is_reported(tmp_path: Path) -> None:
    target = clone(tmp_path)
    agent = target / "Storage" / "remote" / "fail2ban_agent.py"
    agent.write_text(
        agent.read_text(encoding="utf-8") + "\n\ndef wipe():\n    run([\"iptables\", \"-P\", \"INPUT\", \"DROP\"])\n",
        encoding="utf-8",
    )
    result = run_tool(target, "policy")
    assert result.returncode == 1
    assert "default policy" in result.stdout


def test_a_key_injection_guard_removal_is_reported(tmp_path: Path) -> None:
    target = clone(tmp_path)
    agent = target / "Storage" / "remote" / "ssh_agent.py"
    agent.write_text(agent.read_text(encoding="utf-8").replace("def clean_public_key", "def unused_key"), encoding="utf-8")
    run_tool(target, "seal")
    result = run_tool(target, "verify")
    assert result.returncode == 1
    assert "validate a public key" in result.stdout


def test_a_missing_baseline_is_reported(tmp_path: Path) -> None:
    target = clone(tmp_path)
    (target / "tools" / "obhod_protection.baseline.json").unlink()
    result = run_tool(target, "verify")
    assert result.returncode == 1
    assert "baseline is missing" in result.stdout


def test_a_new_protected_file_needs_a_reseal(tmp_path: Path) -> None:
    target = clone(tmp_path)
    baseline = target / "tools" / "obhod_protection.baseline.json"
    body = json.loads(baseline.read_text(encoding="utf-8"))
    body["files"].pop("BOT/seclog.py")
    baseline.write_text(json.dumps(body), encoding="utf-8")
    result = run_tool(target, "verify")
    assert result.returncode == 1
    assert "not in the baseline" in result.stdout


def test_the_cli_rejects_a_unknown_command() -> None:
    result = run_tool(ROOT, "please-break")
    assert result.returncode == 2
    assert "usage" in result.stdout


@pytest.mark.parametrize("name", ["policy", "seal"])
def test_the_cli_commands_work(tmp_path: Path, name: str) -> None:
    target = clone(tmp_path)
    result = run_tool(target, name)
    assert result.returncode == 0
