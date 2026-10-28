from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "tools" / "obhod_protection.baseline.json"

PROTECTED = (
    "BOT/app.py",
    "BOT/audit.py",
    "BOT/guard.py",
    "BOT/inline.py",
    "BOT/ratelimit.py",
    "BOT/seclog.py",
    "BOT/shell.py",
    "Storage/remote/fail2ban_agent.py",
    "Storage/remote/freeturn_agent.py",
    "Storage/remote/ssh_agent.py",
    "Storage/remote/sub_server.py",
    "Storage/remote/xray_agent.py",
    "tools/obhod_watchdog.py",
)

SCANNED = ("BOT", "Storage/remote")

FORBIDDEN_CALLS = (
    r"shell\s*=\s*True",
    r"\bos\.system\(",
    r"\bos\.popen\(",
    r"(?<![A-Za-z0-9_.])eval\(",
    r"(?<![A-Za-z0-9_.])exec\(",
    r"pickle\.loads",
    r"yaml\.load\(",
)

IPTABLES_FORBIDDEN = (
    ('"-P"', "a default policy must never be changed"),
    ("'--policy'", "a default policy must never be changed"),
    ('"-F", "INPUT"', "the INPUT chain must never be flushed"),
    ('"-X", "INPUT"', "the INPUT chain must never be deleted"),
    ('"INPUT", "-j", "DROP"', "INPUT must never get a blanket drop"),
    ('"INPUT", "-j", "ACCEPT"', "INPUT must never get a blanket accept"),
    ("-F INPUT", "the INPUT chain must never be flushed"),
    ("-P INPUT", "a default policy must never be changed"),
)


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def python_files() -> list[Path]:
    out: list[Path] = []
    for entry in SCANNED:
        base = ROOT / entry
        if base.is_file():
            out.append(base)
            continue
        if not base.is_dir():
            continue
        out.extend(sorted(base.glob("*.py")))
    return out


def check_no_dangerous_calls() -> list[str]:
    problems: list[str] = []
    for path in python_files():
        body = read(path)
        for pattern in FORBIDDEN_CALLS:
            match = re.search(pattern, body)
            if match:
                problems.append("%s uses %s" % (path.relative_to(ROOT), match.group(0)))
    return problems


def check_firewall_is_untouched() -> list[str]:
    body = read(ROOT / "Storage" / "remote" / "fail2ban_agent.py")
    problems = []
    for token, reason in IPTABLES_FORBIDDEN:
        if token in body:
            problems.append("fail2ban_agent.py contains %s: %s" % (token, reason))
    return problems


def check_subscription_secrets() -> list[str]:
    body = read(ROOT / "Storage" / "remote" / "sub_server.py")
    problems = []
    if "hmac.compare_digest" not in body:
        problems.append("sub_server.py must compare subscription keys in constant time")
    if '"0" * 64' not in body:
        problems.append("sub_server.py must answer a miss with a dummy comparison")
    if "islink" not in body:
        problems.append("sub_server.py must refuse a linked registry file")
    return problems


def check_owner_gate() -> list[str]:
    body = read(ROOT / "BOT" / "app.py")
    problems = []
    for token, reason in (
        ("who == self.admin_id", "the inline query must be answered only to the owner"),
        ("is_personal=True", "inline results must stay private to one user"),
        ("cache_time=0", "inline results must never be cached by telegram"),
        ("self.admin_id", "the direct message path must keep the admin gate"),
    ):
        if token not in body:
            problems.append("app.py is missing %s: %s" % (token, reason))
    return problems


def check_inline_gate() -> list[str]:
    body = read(ROOT / "BOT" / "inline.py")
    problems = []
    if "hmac.new(" not in body:
        problems.append("inline.py must derive tokens with hmac")
    if "os.urandom(32)" not in body:
        problems.append("inline.py must fall back to a random secret")
    if "MARKER" not in body:
        problems.append("inline.py must keep the delete marker")
    return problems


def check_key_injection() -> list[str]:
    body = read(ROOT / "Storage" / "remote" / "ssh_agent.py")
    problems = []
    if "def clean_public_key" not in body:
        problems.append("ssh_agent.py must validate a public key before writing it")
    if "O_NOFOLLOW" not in body:
        problems.append("ssh_agent.py must not write the key file through a link")
    if "CONTROL" not in body:
        problems.append("ssh_agent.py must refuse control characters in a key")
    return problems


def check_release_allowlist() -> list[str]:
    body = read(ROOT / "Storage" / "remote" / "xray_agent.py")
    problems = []
    if "ALLOWED_HOSTS" not in body or "github.com" not in body:
        problems.append("xray_agent.py must keep the release host allowlist")
    if 'parsed.scheme != "https"' not in body:
        problems.append("xray_agent.py must refuse a release that is not https")
    if "MAX_REDIRECTS" not in body:
        problems.append("xray_agent.py must cap redirects")
    return problems


def check_rate_limits() -> list[str]:
    body = read(ROOT / "BOT" / "ratelimit.py")
    app = read(ROOT / "BOT" / "app.py")
    problems = []
    if "def allow" not in body:
        problems.append("ratelimit.py must keep the allow entry point")
    for limit in ("self.message_limit", "self.callback_limit", "self.inline_limit"):
        if limit not in app:
            problems.append("app.py must keep %s" % limit)
    return problems


def check_no_credentials() -> list[str]:
    problems: list[str] = []
    for path in python_files():
        body = read(path)
        for token in ("ssh_password", "ssh_sudo", "password_authentication=\"yes\" and False"):
            if token in body and path.name != "ssh_agent.py":
                problems.append("%s mentions %s, the bot must hold no credential" % (path.relative_to(ROOT), token))
    store = read(ROOT / "BOT" / "store.py")
    if "0o600" not in store:
        problems.append("store.py must write the state file with mode 0600")
    if "os.replace" not in store:
        problems.append("store.py must replace the state file atomically")
    return problems


def check_subscription_path() -> list[str]:
    body = read(ROOT / "BOT" / "xray.py")
    problems = []
    if "SUB_SEGMENT_LEN" not in body:
        problems.append("xray.py must keep the subscription segment length")
    if "secrets.choice" not in body:
        problems.append("xray.py must draw subscription secrets from secrets")
    if "/sub/" in body:
        problems.append("xray.py must never reuse the 3x-ui subscription path")
    return problems


def check_audit_trail() -> list[str]:
    body = read(ROOT / "BOT" / "audit.py")
    problems = []
    if "SECRET" not in body.upper():
        problems.append("audit.py must keep the secret markers")
    seclog = read(ROOT / "BOT" / "seclog.py")
    if "islink" not in seclog:
        problems.append("seclog.py must refuse a linked log file")
    return problems


POLICIES = (
    ("dangerous_calls", check_no_dangerous_calls),
    ("firewall_untouched", check_firewall_is_untouched),
    ("subscription_secrets", check_subscription_secrets),
    ("owner_gate", check_owner_gate),
    ("inline_gate", check_inline_gate),
    ("key_injection", check_key_injection),
    ("release_allowlist", check_release_allowlist),
    ("rate_limits", check_rate_limits),
    ("no_credentials", check_no_credentials),
    ("subscription_path", check_subscription_path),
    ("audit_trail", check_audit_trail),
)


def policy_report() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, func in POLICIES:
        try:
            problems = func()
        except Exception as exc:
            problems = ["the check crashed: %s" % type(exc).__name__]
        if problems:
            out[name] = problems
    return out


def snapshot() -> dict[str, str]:
    files: dict[str, str] = {}
    for name in PROTECTED:
        path = ROOT / name
        if path.is_file():
            files[name] = digest(path)
    return files


def seal(path: Path | None = None) -> dict[str, object]:
    target = Path(path) if path else BASELINE
    payload = {
        "version": 1,
        "policy": [name for name, _func in POLICIES],
        "files": snapshot(),
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def load(path: Path | None = None) -> dict[str, object]:
    target = Path(path) if path else BASELINE
    try:
        body = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return body if isinstance(body, dict) else {}


def verify(path: Path | None = None) -> list[str]:
    findings: list[str] = []
    for name, problems in policy_report().items():
        for problem in problems:
            findings.append("policy %s: %s" % (name, problem))
    body = load(path)
    if not body:
        findings.append("the baseline is missing or unreadable, run seal")
        return findings
    saved = body.get("files")
    if not isinstance(saved, dict):
        findings.append("the baseline carries no file map")
        return findings
    current = snapshot()
    for name in PROTECTED:
        if name not in current:
            findings.append("%s is missing" % name)
        elif name not in saved:
            findings.append("%s is not in the baseline" % name)
        elif saved[name] != current[name]:
            findings.append("%s changed since the baseline was sealed" % name)
    saved_policy = body.get("policy") or []
    if sorted(saved_policy) != sorted(name for name, _func in POLICIES):
        findings.append("the policy list changed since the baseline was sealed")
    return findings


def main(argv: list[str]) -> int:
    command = argv[0] if argv else "verify"
    if command == "seal":
        payload = seal()
        print("sealed %d files" % len(payload["files"]))
        return 0
    if command == "policy":
        report = policy_report()
        for name, problems in report.items():
            for problem in problems:
                print("%s: %s" % (name, problem))
        print("policy checks %s" % ("failed" if report else "passed"))
        return 1 if report else 0
    if command == "verify":
        findings = verify()
        for item in findings:
            print(item)
        print("protection %s" % ("drifted" if findings else "intact"))
        return 1 if findings else 0
    print("usage: obhod_watchdog.py [verify|seal|policy]")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
