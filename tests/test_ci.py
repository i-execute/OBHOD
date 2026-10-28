from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
PINNED = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)+@v[0-9]+$")


def files() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml"))


def load(path: Path) -> dict:
    body = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(body, dict)
    return body


def steps_of(body: dict) -> list[dict]:
    out: list[dict] = []
    for job in (body.get("jobs") or {}).values():
        out.extend(job.get("steps") or [])
    return out


def text_of(body: dict) -> str:
    parts: list[str] = []
    for step in steps_of(body):
        if step.get("run"):
            parts.append(str(step["run"]))
    return "\n".join(parts)


def test_workflows_exist() -> None:
    names = {path.name for path in files()}
    assert {"ci.yml", "codeql.yml", "protection.yml"} <= names


@pytest.mark.parametrize("path", files(), ids=lambda item: item.name)
def test_a_workflow_is_cheap_and_safe(path: Path) -> None:
    body = load(path)
    assert body.get("permissions"), "%s needs an explicit permission block" % path.name
    assert "write-all" not in str(body.get("permissions"))
    assert "pull_request_target" not in body.get(True, {}) and "pull_request_target" not in yaml.safe_dump(body)
    assert body.get("concurrency", {}).get("cancel-in-progress") is True
    for job_name, job in (body.get("jobs") or {}).items():
        assert job.get("timeout-minutes"), "%s/%s needs a timeout" % (path.name, job_name)
        assert job.get("runs-on") == "ubuntu-latest"


@pytest.mark.parametrize("path", files(), ids=lambda item: item.name)
def test_every_action_is_pinned_to_a_major_version(path: Path) -> None:
    for step in steps_of(load(path)):
        uses = step.get("uses")
        if uses:
            assert PINNED.match(uses), "%s uses an unpinned action %s" % (path.name, uses)


@pytest.mark.parametrize("path", files(), ids=lambda item: item.name)
def test_checkout_never_keeps_credentials(path: Path) -> None:
    for step in steps_of(load(path)):
        if str(step.get("uses", "")).startswith("actions/checkout"):
            assert (step.get("with") or {}).get("persist-credentials") is False


def test_the_ci_runs_the_tests_and_the_lint() -> None:
    body = load(WORKFLOWS / "ci.yml")
    commands = text_of(body)
    assert "python -m pytest" in commands
    assert "pyflakes" in commands
    assert "tools/obhod_watchdog.py verify" in commands
    assert "tools/obhod_watchdog.py policy" in commands
    triggers = yaml.safe_load((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))[True]
    assert "push" in triggers
    assert "pull_request" in triggers


def test_the_protection_workflow_watches_the_protected_paths() -> None:
    body = load(WORKFLOWS / "protection.yml")
    triggers = body[True]
    paths = triggers["pull_request"]["paths"]
    assert "BOT/**" in paths
    assert "Storage/**" in paths
    assert "tools/**" in paths
    commands = text_of(body)
    assert "obhod_watchdog.py policy" in commands
    assert "obhod_watchdog.py verify" in commands


def test_codeql_runs_on_a_schedule() -> None:
    body = load(WORKFLOWS / "codeql.yml")
    assert "schedule" in body[True]
    assert body["permissions"].get("security-events") == "write"


def test_no_workflow_writes_to_the_repository() -> None:
    for path in files():
        permissions = load(path).get("permissions") or {}
        assert permissions.get("contents", "read") == "read"
        assert "write" not in str(permissions.get("contents"))


def test_dependabot_keeps_the_actions_and_python_current() -> None:
    body = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    ecosystems = {item["package-ecosystem"] for item in body["updates"]}
    assert ecosystems == {"pip", "github-actions"}
    for item in body["updates"]:
        assert item["open-pull-requests-limit"] <= 5


def test_the_dev_requirements_are_separate_from_runtime() -> None:
    runtime = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    dev = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "goygram" in runtime
    assert "pytest" not in runtime
    for name in ("pytest", "pyflakes", "PyYAML"):
        assert name in dev
