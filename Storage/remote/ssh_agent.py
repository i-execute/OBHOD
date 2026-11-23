import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

PROTO = 3
LOGS = []
SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_MAIN = "/etc/ssh/sshd_config.d/00-obhod.conf"
ROOT_CHOICES = ("yes", "no", "prohibit-password", "forced-commands-only")


class ScriptError(Exception):
    def __init__(self, code, message, stage="ssh"):
        super().__init__(message)
        self.code = code
        self.message = message
        self.stage = stage


def note(text):
    LOGS.append(str(text))


def run(argv, timeout=120):
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)
    return proc.returncode, proc.stdout or ""


def have(tool):
    return shutil.which(tool) is not None


def read_config():
    try:
        with open(SSHD_CONFIG, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def option_of(text, name):
    value = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.replace("=", " ").split()
        if len(parts) >= 2 and parts[0].lower() == name:
            value = parts[1]
    return value


def ports_of(text):
    ports = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.replace("=", " ").split()
        if len(parts) >= 2 and parts[0].lower() == "port":
            token = parts[1]
            if not token.isdigit() or len(token) > 5:
                continue
            value = int(token)
            if 0 < value < 65536 and value not in ports:
                ports.append(value)
    return ports or [22]


def authorized_key_owner():
    try:
        entries = [item for item in os.listdir("/home") if os.path.isdir(os.path.join("/home", item))]
    except OSError:
        entries = []
    for name in entries:
        if os.path.isdir(os.path.join("/home", name, ".ssh")):
            return name, os.path.join("/home", name, ".ssh", "authorized_keys")
    return "root", "/root/.ssh/authorized_keys"


KEY_TYPES = ("ssh-", "ecdsa-", "sk-")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
KEY_BODY = re.compile(r"[A-Za-z0-9+/=]{1,4096}")
KEY_COMMENT = re.compile(r"[\x20-\x7e]{0,128}")


def clean_public_key(text):
    body = str(text or "")
    if CONTROL.search(body):
        raise ScriptError("bad_arg", "a public key cannot carry control characters", "key")
    if "\n" in body or "\r" in body:
        raise ScriptError("bad_arg", "a public key must be one line", "key")
    body = body.strip()
    if not body.startswith(KEY_TYPES):
        raise ScriptError("bad_arg", "the value is not a public key", "key")
    parts = body.split()
    if len(parts) < 2:
        raise ScriptError("bad_arg", "the value is not a public key", "key")
    if not KEY_BODY.match(parts[1]):
        raise ScriptError("bad_arg", "the key body is not base64", "key")
    comment = " ".join(parts[2:])
    if comment and not KEY_COMMENT.match(comment):
        raise ScriptError("bad_arg", "the key comment has unexpected characters", "key")
    return parts[0] + " " + parts[1] + ((" " + comment) if comment else "")


def key_identity(line):
    parts = str(line).strip().split()
    if len(parts) < 2:
        return ""
    return parts[0] + " " + parts[1]


def key_list(path):
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return out
    for line in lines:
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        parts = token.split()
        if len(parts) < 2:
            continue
        kind = parts[0]
        blob = parts[1]
        comment = " ".join(parts[2:])[:48] if len(parts) > 2 else ""
        fingerprint = ""
        try:
            padded = blob + "=" * (-len(blob) % 4)
            digest = hashlib.sha256(base64.b64decode(padded, validate=False)).digest()
            fingerprint = "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")[:43]
        except (ValueError, TypeError):
            fingerprint = ""
        out.append({"type": kind, "comment": comment, "fingerprint": fingerprint, "bytes": len(blob)})
        if len(out) >= 32:
            break
    return out


def key_count(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return len([line for line in handle.read().splitlines() if line.strip() and not line.startswith("#")])
    except OSError:
        return 0


def status(_flags):
    text = read_config()
    user, keys = authorized_key_owner()
    service = "absent"
    if have("systemctl"):
        code, out = run(["systemctl", "is-active", "ssh.service"], timeout=30)
        service = out.strip() or "unknown"
        if code != 0 and service not in {"active", "activating"}:
            code, out = run(["systemctl", "is-active", "sshd.service"], timeout=30)
            service = out.strip() or service
    return {
        "config": SSHD_CONFIG,
        "config_exists": os.path.isfile(SSHD_CONFIG),
        "dropin": SSHD_MAIN,
        "dropin_exists": os.path.isfile(SSHD_MAIN),
        "ports": ports_of(text),
        "permit_root_login": option_of(text, "permitrootlogin") or "prohibit-password",
        "password_authentication": option_of(text, "passwordauthentication") or "yes",
        "pubkey_authentication": option_of(text, "pubkeyauthentication") or "yes",
        "key_user": user,
        "key_path": keys,
        "keys": key_count(keys),
        "key_list": key_list(keys),
        "service": service,
        "sshd": have("sshd") or os.path.isfile("/usr/sbin/sshd"),
        "systemd": have("systemctl"),
    }


def write_dropin(body):
    folder = os.path.dirname(SSHD_MAIN)
    if not os.path.isdir(folder):
        os.makedirs(folder, exist_ok=True)
    with open(SSHD_MAIN, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(SSHD_MAIN, 0o600)
    note("the ssh dropin is written")


def test_config():
    binary = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.isfile("/usr/sbin/sshd") else "")
    if not binary:
        return True, ""
    code, text = run([binary, "-t"], timeout=60)
    return code == 0, text


def restart():
    if not have("systemctl"):
        raise ScriptError("no_systemd", "systemd is required to restart ssh", "restart")
    for unit in ("ssh.service", "sshd.service"):
        code, _text = run(["systemctl", "restart", unit], timeout=120)
        if code == 0:
            return
    raise ScriptError("start_failed", "the ssh service did not restart", "restart")


def apply(flags):
    port = str(flags.get("port", "")).strip()
    password = str(flags.get("password", "")).strip().lower()
    root = str(flags.get("root", "")).strip().lower()
    lines = ["", ""]
    if port:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ScriptError("bad_arg", "the port must be between 1 and 65535", "apply")
        lines.append("Port " + port)
    if password in {"yes", "no"}:
        lines.append("PasswordAuthentication " + password)
        lines.append("KbdInteractiveAuthentication " + password)
    if root:
        if root not in ROOT_CHOICES:
            raise ScriptError("bad_arg", "the root login value is not supported", "apply")
        lines.append("PermitRootLogin " + root)
    if len(lines) <= 2:
        raise ScriptError("bad_arg", "no ssh option was supplied", "apply")
    if password == "no":
        user, keys = authorized_key_owner()
        present = key_list(keys)
        if not present:
            raise ScriptError(
                "no_keys",
                "password login is not touched: the account %s has no public key in %s, so disabling the password "
                "would lock every login out. Add a key first, then repeat this action." % (user, keys),
                "apply",
            )
        if len(present) > 32:
            raise ScriptError("bad_arg", "the key file is too long to verify safely", "apply")
    lines.append("PubkeyAuthentication yes")
    lines.append("MaxAuthTries 3")
    lines.append("MaxSessions 10")
    lines.append("LoginGraceTime 20")
    lines.append("ClientAliveInterval 300")
    lines.append("ClientAliveCountMax 2")
    lines.append("X11Forwarding no")
    lines.append("AllowAgentForwarding no")
    lines.append("AllowTcpForwarding no")
    lines.append("PermitTunnel no")
    lines.append("")
    previous = ""
    if os.path.isfile(SSHD_MAIN):
        with open(SSHD_MAIN, "r", encoding="utf-8", errors="replace") as handle:
            previous = handle.read()
    write_dropin("\n".join(lines))
    ok, text = test_config()
    if not ok:
        if previous:
            write_dropin(previous)
        else:
            try:
                os.unlink(SSHD_MAIN)
            except OSError:
                pass
        raise ScriptError("config_invalid", "sshd rejected the configuration: " + text[:400], "apply")
    restart()
    return status(flags)


def add_key(flags):
    raw = str(flags.get("key_b64", ""))
    if not raw:
        raise ScriptError("bad_arg", "the public key is required", "key")
    try:
        body = base64.b64decode(raw).decode("utf-8", "replace").strip()
    except (ValueError, TypeError):
        raise ScriptError("bad_arg", "the public key is not decodable", "key")
    body = clean_public_key(body)
    user, path = authorized_key_owner()
    folder = os.path.dirname(path)
    if not os.path.isdir(folder):
        os.makedirs(folder, exist_ok=True)
        os.chmod(folder, 0o700)
    existing = ""
    if os.path.islink(path):
        raise ScriptError("bad_arg", "the key file is a link, refusing to write through it", "key")
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            existing = handle.read()
    known = set()
    for line in existing.splitlines():
        if line.strip() and not line.strip().startswith("#"):
            known.add(key_identity(line))
    identity = key_identity(body)
    if not identity:
        raise ScriptError("bad_arg", "the value is not a public key", "key")
    if identity in known:
        note("the public key is already present")
        return status(flags)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        payload = (("\n" if existing and not existing.endswith("\n") else "") + body + "\n").encode("utf-8")
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)
    note("the public key is added")
    return status(flags)


def remove_dropin(flags):
    if os.path.isfile(SSHD_MAIN):
        try:
            os.unlink(SSHD_MAIN)
        except OSError:
            pass
        note("the ssh dropin is removed")
        restart()
    return status(flags)


def parse_flags(tokens):
    flags = {}
    rest = []
    for token in tokens:
        if token.startswith("--"):
            body = token[2:]
            if "=" in body:
                key, value = body.split("=", 1)
                flags[key.replace("-", "_")] = value
            else:
                flags[body.replace("-", "_")] = True
        else:
            rest.append(token)
    return flags, rest


def emit(payload):
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    sys.stdout.flush()


COMMANDS = {
    "status": status,
    "apply": apply,
    "key": add_key,
    "remove": remove_dropin,
}


def main(argv):
    if not argv:
        emit({"proto": PROTO, "result": "err", "code": "bad_arg", "msg": "no command was given", "stage": "args"})
        return 2
    handler = COMMANDS.get(argv[0])
    if handler is None:
        emit({"proto": PROTO, "result": "err", "code": "bad_arg", "msg": "unknown command %s" % argv[0], "stage": "args"})
        return 2
    flags, _rest = parse_flags(argv[1:])
    try:
        data = handler(flags)
    except ScriptError as exc:
        emit({"proto": PROTO, "result": "err", "code": exc.code, "msg": exc.message, "stage": exc.stage, "logs": LOGS})
        return 1
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        emit({"proto": PROTO, "result": "err", "code": "internal", "msg": str(exc)[:600], "stage": argv[0], "logs": LOGS})
        return 1
    emit({"proto": PROTO, "result": "ok", "data": data, "logs": LOGS})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
