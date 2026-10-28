import errno
import json
import ipaddress
import os
import re
import shutil
import subprocess
import sys

PROTO = 3
LOGS = []

JAIL = "3x-ipl"
JAIL_SSH = "obhod-sshd"
FAIL2BAN_DIR = "/etc/fail2ban"
FILTER_DIR = "/etc/fail2ban/filter.d"
JAIL_DIR = "/etc/fail2ban/jail.d"
ACTION_DIR = "/etc/fail2ban/action.d"
JAIL_FILE = os.path.join(JAIL_DIR, "3x-ipl.conf")
FILTER_FILE = os.path.join(FILTER_DIR, "3x-ipl.conf")
ACTION_FILE = os.path.join(ACTION_DIR, "3x-ipl.conf")
XRAY_LOG = "/var/log/xray/access.log"
SUB_LOG = "/var/log/xray/sub.log"
JAIL_SUB = "obhod-subs"
JAIL_SEC = "obhod-security"
SECLOG = "/var/log/obhod/security.log"
SECURITY_FILTER_NAME = "obhod-security.conf"
DEFAULT_SEC_MAXRETRY = 20
DEFAULT_SEC_FINDTIME = 1800
DEFAULT_SEC_BANTIME = "1h"
CHAIN = "OBHOD-IPL"
DEFAULT_BANTIME = 30
DEFAULT_SSH_BANTIME = "3d"
DEFAULT_SSH_FINDTIME = 3600
DEFAULT_SSH_MAXRETRY = 3
DEFAULT_IGNORE = "127.0.0.1/8 ::1"
DURATION = re.compile(r"^[1-9][0-9]{0,4}[smhdw]$")

LIMIT_FILTER = "\n".join(
    [
        "[Definition]",
        "failregex = \\[LIMIT_IP\\]\\s*Email\\s*=\\s*<F-USER>.+?</F-USER>\\s*\\|\\|\\s*Disconnecting OLD IP\\s*=\\s*<ADDR>\\s*\\|\\|\\s*Timestamp\\s*=\\s*\\d+",
        "ignoreregex =",
        "",
    ]
)

REJECT_FILTER = "\n".join(
    [
        "[Definition]",
        "failregex = ^.*(REALITY: processed invalid connection|failed to read client hello|invalid request version|unknown transport protocol).*[\\s\\[(]tcp:(?:[0-9a-f:.]+:)?<ADDR>:\\d+.*$",
        "ignoreregex =",
        "",
    ]
)

SUB_FILTER = "\n".join(
    [
        "[Definition]",
        "failregex = ^sub 40[34] <ADDR>$",
        "ignoreregex =",
        "",
    ]
)

SECURITY_FILTER = "\n".join(
    [
        "[Definition]",
        "failregex = ^security ip=<HOST> event=\\S+ outcome=(?:deny|block) actor=\\d+ detail=\\S+$",
        "ignoreregex =",
        "",
    ]
)

ACTION = "\n".join(
    [
        "[Definition]",
        "actionstart = iptables -S {chain} >/dev/null 2>&1 || iptables -N {chain}; "
        "for p in <exemptports>; do iptables -C {chain} -p tcp --dport $p -j RETURN 2>/dev/null || "
        "iptables -A {chain} -p tcp --dport $p -j RETURN; done; "
        "iptables -C INPUT -j {chain} 2>/dev/null || iptables -A INPUT -j {chain}; "
        "ip6tables -S {chain} >/dev/null 2>&1 || ip6tables -N {chain}; "
        "for p in <exemptports>; do ip6tables -C {chain} -p tcp --dport $p -j RETURN 2>/dev/null || "
        "ip6tables -A {chain} -p tcp --dport $p -j RETURN 2>/dev/null; done; "
        "ip6tables -C INPUT -j {chain} 2>/dev/null || ip6tables -A INPUT -j {chain} 2>/dev/null; true",
        "actionstop = iptables -D INPUT -j {chain} 2>/dev/null; iptables -X {chain} 2>/dev/null; "
        "ip6tables -D INPUT -j {chain} 2>/dev/null; ip6tables -X {chain} 2>/dev/null; true",
        "actioncheck = iptables -n -L INPUT | grep -q {chain}",
        "actionban = iptables -C {chain} -s <ip> -j DROP 2>/dev/null || iptables -A {chain} -s <ip> -j DROP 2>/dev/null; "
        "ip6tables -C {chain} -s <ip> -j DROP 2>/dev/null || ip6tables -A {chain} -s <ip> -j DROP 2>/dev/null; true",
        "actionunban = iptables -D {chain} -s <ip> -j DROP 2>/dev/null; "
        "ip6tables -D {chain} -s <ip> -j DROP 2>/dev/null; true",
        "[Init]",
        "exemptports = {ports}",
        "",
    ]
).format(chain=CHAIN, ports="__PORTS__")


class ScriptError(Exception):
    def __init__(self, code, message, stage="fail2ban"):
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


def ssh_port():
    code, text = run(["bash", "-lc", "ss -tlnp 2>/dev/null | grep -o 'sshd' | head -n1"])
    ports = []
    conf = "/etc/ssh/sshd_config"
    if os.path.isfile(conf):
        try:
            with open(conf, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    token = line.strip()
                    if token.lower().startswith("port ") and token.split()[-1].isdigit():
                        ports.append(int(token.split()[-1]))
        except OSError:
            ports = []
    if not ports:
        ports = [22]
    return ports


def auth_log_path():
    for candidate in ("/var/log/auth.log", "/var/log/secure"):
        if os.path.isfile(candidate):
            return candidate
    return "/var/log/auth.log"


def exempt_ports(extra):
    ports = ssh_port()
    for item in extra:
        try:
            value = int(item)
        except (TypeError, ValueError):
            continue
        if value not in ports:
            ports.append(value)
    return ports


def write_reason(target, exc):
    number = getattr(exc, "errno", 0)
    if number == errno.EROFS:
        return (
            "the file system is read only at %s, the service unit of the bot must list that directory "
            "in ReadWritePaths because it runs with ProtectSystem=strict" % target
        )
    if number in (errno.EACCES, errno.EPERM):
        return "the bot is not allowed to write %s" % target
    return "the file %s could not be written: %s" % (target, getattr(exc, "strerror", "") or str(exc))


def write_file(target, body, mode=0o644):
    folder = os.path.dirname(target)
    try:
        if not os.path.isdir(folder):
            os.makedirs(folder, exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.chmod(target, mode)
    except OSError as exc:
        raise ScriptError("write_failed", write_reason(target, exc), "write") from None


IP_OR_NET = re.compile(r"^[0-9A-Fa-f:.]{2,64}(/[0-9]{1,3})?$")
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]{1,200}$")


def safe_address(value, label="the ip address"):
    text = str(value or "").strip()
    if not text or not IP_OR_NET.match(text) or ".." in text:
        raise ScriptError("bad_arg", "%s is not an address or a network" % label, "args")
    try:
        ipaddress.ip_network(text, strict=False) if "/" in text else ipaddress.ip_address(text)
    except ValueError:
        raise ScriptError("bad_arg", "%s is not a real address or network" % label, "args") from None
    return text


def safe_ignore(value):
    text = str(value or "").strip() or DEFAULT_IGNORE
    items = [item for item in text.replace(",", " ").split() if item]
    if len(items) > 16:
        raise ScriptError("bad_arg", "the ignore list is too long", "args")
    checked = [safe_address(item, "the ignore list entry") for item in items]
    return " ".join(checked) or DEFAULT_IGNORE


def safe_path(value, label="the log path"):
    text = str(value or "").strip()
    if not SAFE_PATH.match(text) or ".." in text.split("/"):
        raise ScriptError("bad_arg", "%s must be a simple absolute path" % label, "args")
    return text


def safe_port_list(values):
    out = []
    for item in values:
        try:
            port = int(item)
        except (TypeError, ValueError):
            raise ScriptError("bad_arg", "the port must be a number", "args") from None
        if not 1 <= port <= 65535:
            raise ScriptError("bad_arg", "the port must be between 1 and 65535", "args")
        if port not in out:
            out.append(port)
    return out


def duration_of(value, default):
    text = str(value or "").strip().lower()
    if DURATION.match(text):
        return text
    return default


def seconds_of(value, default):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(60, min(604800, number))


def minutes_of(value, default):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(525600, number))


def jail_body(
    bantime,
    findtime,
    maxretry,
    logpath,
    ssh,
    ports,
    auth_log="",
    ignore=DEFAULT_IGNORE,
    ssh_bantime=DEFAULT_SSH_BANTIME,
    ssh_findtime=DEFAULT_SSH_FINDTIME,
    ssh_maxretry=DEFAULT_SSH_MAXRETRY,
    sub_log=SUB_LOG,
    sub_maxretry=20,
    sec_log=SECLOG,
    security=True,
    sec_maxretry=DEFAULT_SEC_MAXRETRY,
    sec_findtime=DEFAULT_SEC_FINDTIME,
    sec_bantime=DEFAULT_SEC_BANTIME,
):
    lines = [
        "[{}]".format(JAIL),
        "enabled = true",
        "filter = 3x-ipl",
        "action = 3x-ipl",
        "logpath = " + logpath,
        "maxretry = {}".format(minutes_of(maxretry, 1)),
        "findtime = {}".format(seconds_of(findtime, 1920)),
        "bantime = {}m".format(minutes_of(bantime, DEFAULT_BANTIME)),
        "backend = auto",
        "ignoreip = " + ignore,
        "",
        "[{}]".format(JAIL_SSH),
        "enabled = {}".format("true" if ssh else "false"),
        "filter = sshd",
        "port = " + ",".join(str(item) for item in ports),
        "logpath = " + (auth_log or "/var/log/auth.log"),
        "maxretry = {}".format(minutes_of(ssh_maxretry, DEFAULT_SSH_MAXRETRY)),
        "findtime = {}".format(seconds_of(ssh_findtime, DEFAULT_SSH_FINDTIME)),
        "bantime = " + duration_of(ssh_bantime, DEFAULT_SSH_BANTIME),
        "backend = auto",
        "ignoreip = " + ignore,
        "",
        "[{}]".format(JAIL_SUB),
        "enabled = true",
        "filter = obhod-subs",
        "action = 3x-ipl",
        "logpath = " + sub_log,
        "maxretry = {}".format(minutes_of(sub_maxretry, 20)),
        "findtime = {}".format(seconds_of(600, 600)),
        "bantime = " + duration_of(ssh_bantime, DEFAULT_SSH_BANTIME),
        "backend = auto",
        "ignoreip = " + ignore,
        "",
        "[{}]".format(JAIL_SEC),
        "enabled = {}".format("true" if security else "false"),
        "filter = obhod-security",
        "action = 3x-ipl",
        "logpath = " + sec_log,
        "maxretry = {}".format(minutes_of(sec_maxretry, DEFAULT_SEC_MAXRETRY)),
        "findtime = {}".format(seconds_of(sec_findtime, DEFAULT_SEC_FINDTIME)),
        "bantime = " + duration_of(sec_bantime, DEFAULT_SEC_BANTIME),
        "backend = auto",
        "ignoreip = " + ignore,
        "",
    ]
    return "\n".join(lines)


def security_paths():
    return os.path.join(FILTER_DIR, SECURITY_FILTER_NAME), os.path.join(JAIL_DIR, SECURITY_FILTER_NAME)


def jail_state(name):
    if not have("fail2ban-client"):
        return {"name": name, "present": False, "banned": []}
    code, text = run(["fail2ban-client", "status", name], timeout=60)
    present = code == 0
    banned = []
    if present:
        for line in text.splitlines():
            token = line.strip()
            if token.lower().startswith("banned ip list"):
                body = token.split(":", 1)[1] if ":" in token else ""
                banned = [item for item in body.split() if item]
    return {"name": name, "present": present, "banned": banned}


def report(port):
    installed = have("fail2ban-client") and have("iptables")
    state = {"installed": installed, "jail": JAIL, "ssh_jail": JAIL_SSH, "sub_jail": JAIL_SUB, "security_jail": JAIL_SEC, "jails": [], "chain": CHAIN}
    if installed:
        code, text = run(["fail2ban-client", "status"], timeout=60)
        if code == 0:
            for line in text.splitlines():
                token = line.strip()
                if token.lower().startswith("jail list"):
                    body = token.split(":", 1)[1] if ":" in token else ""
                    state["jails"] = [item.strip() for item in body.split(",") if item.strip()]
        state["main"] = jail_state(JAIL)
        state["ssh"] = jail_state(JAIL_SSH)
        state["subs"] = jail_state(JAIL_SUB)
        state["security"] = jail_state(JAIL_SEC)
    if port:
        state["port"] = int(port)
    code, text = run(["iptables", "-n", "-L", CHAIN], timeout=30)
    state["chain_rules"] = [line for line in text.splitlines()[2:] if line.strip()] if code == 0 else []
    code, text = run(["ip6tables", "-n", "-L", CHAIN], timeout=30)
    state["chain6_rules"] = [line for line in text.splitlines()[2:] if line.strip()] if code == 0 else []
    return state


def install(flags):
    if not have("fail2ban-client") or not os.path.isdir(FAIL2BAN_DIR):
        raise ScriptError("not_installed", "fail2ban is not installed on the server", "install")
    if not have("iptables"):
        raise ScriptError("not_installed", "iptables is not available on the server", "install")
    bantime = minutes_of(flags.get("bantime", DEFAULT_BANTIME), DEFAULT_BANTIME)
    findtime = seconds_of(flags.get("findtime", 1920), 1920)
    maxretry = minutes_of(flags.get("maxretry", 1), 1)
    ssh_bantime = duration_of(flags.get("ssh_bantime", DEFAULT_SSH_BANTIME), DEFAULT_SSH_BANTIME)
    ssh_findtime = seconds_of(flags.get("ssh_findtime", DEFAULT_SSH_FINDTIME), DEFAULT_SSH_FINDTIME)
    ssh_maxretry = minutes_of(flags.get("ssh_maxretry", DEFAULT_SSH_MAXRETRY), DEFAULT_SSH_MAXRETRY)
    ignore = safe_ignore(flags.get("ignoreip", DEFAULT_IGNORE))
    logpath = safe_path(flags.get("logpath", XRAY_LOG), "the access log path")
    sub_log = safe_path(flags.get("sublog", SUB_LOG), "the subscription log path")
    sec_log = safe_path(flags.get("seclog", SECLOG), "the security log path")
    security = flag_on(flags.get("security"), True)
    sec_maxretry = minutes_of(flags.get("secmaxretry", DEFAULT_SEC_MAXRETRY), DEFAULT_SEC_MAXRETRY)
    sec_findtime = seconds_of(flags.get("secfindtime", DEFAULT_SEC_FINDTIME), DEFAULT_SEC_FINDTIME)
    sec_bantime = duration_of(flags.get("secbantime", DEFAULT_SEC_BANTIME), DEFAULT_SEC_BANTIME)
    port = str(flags.get("port", ""))
    if port:
        port = str(safe_port_list([port])[0])
    ssh = flag_on(flags.get("ssh"), True)
    ports = exempt_ports([port] if port else [])
    write_file(FILTER_FILE, LIMIT_FILTER)
    write_file(os.path.join(FILTER_DIR, "xray-reject.conf"), REJECT_FILTER)
    write_file(os.path.join(FILTER_DIR, "obhod-subs.conf"), SUB_FILTER)
    write_file(os.path.join(FILTER_DIR, SECURITY_FILTER_NAME), SECURITY_FILTER)
    write_file(ACTION_FILE, ACTION.replace("__PORTS__", " ".join(str(item) for item in ports)))
    write_file(
        os.path.join(JAIL_DIR, "xray-reject.conf"),
        "\n".join(
            [
                "[xray-reject]",
                "enabled = true",
                "filter = xray-reject",
                "action = 3x-ipl",
                "logpath = " + logpath,
                "maxretry = 3",
                "findtime = 300",
                "bantime = {}m".format(minutes_of(bantime, DEFAULT_BANTIME)),
                "backend = auto",
                "ignoreip = " + ignore,
                "",
            ]
        ),
    )
    write_file(
        JAIL_FILE,
        jail_body(
            bantime,
            findtime,
            maxretry,
            logpath,
            ssh,
            ports,
            auth_log_path(),
            ignore,
            ssh_bantime,
            ssh_findtime,
            ssh_maxretry,
            sub_log,
            minutes_of(flags.get("submaxretry", 20), 20),
            sec_log,
            security,
            sec_maxretry,
            sec_findtime,
            sec_bantime,
        ),
    )
    for target in (logpath, sub_log, sec_log):
        folder = os.path.dirname(target)
        if folder and not os.path.isdir(folder):
            os.makedirs(folder, exist_ok=True)
        if folder and not os.path.isfile(target):
            with open(target, "a", encoding="utf-8"):
                pass
    note("jail files are written")
    code, text = run(["fail2ban-client", "-t"], timeout=120)
    if code != 0:
        raise ScriptError("config_invalid", "fail2ban rejected the configuration: " + text[:400], "test")
    if not have("systemctl"):
        raise ScriptError("no_systemd", "systemd is required to run fail2ban", "start")
    run(["systemctl", "enable", "fail2ban"], timeout=90)
    code, text = run(["systemctl", "restart", "fail2ban"], timeout=180)
    if code != 0:
        raise ScriptError("start_failed", "fail2ban did not start: " + text[:400], "start")
    return report(port)


def uninstall(flags):
    for target in (
        JAIL_FILE,
        os.path.join(JAIL_DIR, "xray-reject.conf"),
        FILTER_FILE,
        os.path.join(FILTER_DIR, "xray-reject.conf"),
        os.path.join(FILTER_DIR, "obhod-subs.conf"),
        *security_paths(),
    ):
        if os.path.isfile(target):
            try:
                os.unlink(target)
            except OSError:
                pass
    run(["fail2ban-client", "unban", "--all"], timeout=60)
    code, text = run(["iptables", "-D", "INPUT", "-j", CHAIN], timeout=30)
    run(["iptables", "-F", CHAIN], timeout=30)
    run(["iptables", "-X", CHAIN], timeout=30)
    if have("systemctl"):
        run(["systemctl", "restart", "fail2ban"], timeout=180)
    note("jail files are removed")
    return report(str(flags.get("port", "")))


def set_ban(flags, ban):
    address = safe_address(flags.get("ip", ""))
    if not have("fail2ban-client"):
        raise ScriptError("not_installed", "fail2ban is not installed on the server", "ban")
    action = "banip" if ban else "unbanip"
    code, text = run(["fail2ban-client", "set", JAIL, action, address], timeout=60)
    if code != 0:
        raise ScriptError("internal", "fail2ban refused the change: " + text[:300], "ban")
    return report(str(flags.get("port", "")))


OFF_TEXT = {"0", "no", "false", "off", "disabled", "none", ""}


def flag_on(value, default=True):
    if value is None:
        return bool(default)
    if value is True:
        return True
    if value is False:
        return False
    return str(value).strip().lower() not in OFF_TEXT


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


COMMANDS = {
    "install": install,
    "remove": uninstall,
    "status": lambda flags: report(str(flags.get("port", ""))),
    "ban": lambda flags: set_ban(flags, True),
    "unban": lambda flags: set_ban(flags, False),
}


def emit(payload):
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    sys.stdout.flush()


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
