from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
import time
try:
    from rich.console import Console
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

import threading
_SPIN_FRAMES = [chr(47), chr(45), chr(92), chr(124)]
_SPIN_FRAMES_ASCII = ["/","-","\\","|"]
class Spinner:
    def __init__(self, msg: str):
        self.msg = msg
        self._stop = threading.Event()
        self._thr: threading.Thread | None = None
        self._use_rich = False
    def __enter__(self):
        if COLOR and sys.stdout.isatty():
            frames = _SPIN_FRAMES if sys.stdout.encoding and "utf" in sys.stdout.encoding.lower() else _SPIN_FRAMES_ASCII
            def _run():
                import time
                i=0
                while not self._stop.is_set():
                    sys.stdout.write("\r  %s %s   " % (frames[i % len(frames)], self.msg))
                    sys.stdout.flush()
                    i+=1
                    time.sleep(0.08)
            self._thr = threading.Thread(target=_run, daemon=True)
            self._thr.start()
        else:
            print("      .. " + self.msg)
        return self
    def ok(self, done_msg: str = "", extra: str = ""):
        if self._thr:
            self._stop.set(); self._thr.join(timeout=0.3)
            sys.stdout.write("\r  \033[38;5;42m[ok]\033[0m %s" % (done_msg or self.msg))
            if extra: sys.stdout.write(" \033[2m%s\033[0m" % extra)
            sys.stdout.write("          \n"); sys.stdout.flush()
        else:
            print("      \033[38;5;42mok\033[0m " + (done_msg or self.msg))
    def fail(self, msg: str = ""):
        if self._thr:
            self._stop.set(); self._thr.join(timeout=0.3)
            sys.stdout.write("\r  \033[38;5;203mx\033[0m %s          \n" % (msg or self.msg)); sys.stdout.flush()
        else:
            print("      \033[38;5;203mxx\033[0m " + (msg or self.msg))
    def __exit__(self, *a):
        if self._thr and not self._stop.is_set():
            self.ok()
from pathlib import Path

OK = "ok"
BAD = "bad"
WARN = "warn"
INFO = "info"
TITLE = "OBHOD setup"
DEFAULT_PREFIX = "/opt/obhod"
SECRET_ENV = ("BOT_TOKEN", "API_HASH")
THEME = {
    "border": "38;5;141",
    "header": "1;38;5;45",
    "accent": "38;5;44",
    "ok": "38;5;42",
    "warn": "38;5;214",
    "bad": "38;5;203",
    "dim": "38;5;244",
}
TOKEN_RE = re.compile(r"^[0-9]{5,}:[A-Za-z0-9_-]{30,}$")
HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def mask_secret(name: str, value: str) -> str:
    if not value:
        return "missing"
    if name == "BOT_TOKEN" and ":" in value:
        return value.split(":", 1)[0] + ":****"
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


def use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("OBHOD_NO_UI") == "1":
        return False
    return sys.stdout.isatty()


COLOR = use_color()


def paint(text: str, code: str) -> str:
    if not COLOR:
        return text
    return "\033[%sm%s\033[0m" % (code, text)


def head(text: str) -> None:
    print()
    width = 56
    print(paint("  +" + "=" * width + "+", "38;5;45"))
    print(paint("  | " + text.ljust(width-1) + "|", "1;38;5;45"))
    print(paint("  +" + "=" * width + "+", "38;5;45"))


def line(kind: str, text: str) -> None:
    mark = {OK: ("ok", "38;5;42"), BAD: ("error", "38;5;203"), WARN: ("warn", "38;5;214"), INFO: ("..", "38;5;244")}[kind]
    print("  %-6s %s" % (paint(mark[0], mark[1]), text))


def note(text: str) -> None:
    print("         %s" % paint(text, "38;5;244"))


def fail(text: str) -> int:
    line(BAD, text)
    return 1


class Setup:
    def __init__(self, argv: list[str]) -> None:
        self.argv = argv
        self.prefix = DEFAULT_PREFIX
        self.env_file = ""
        self.state_dir = "/var/lib/obhod"
        self.python = os.environ.get("OBHOD_PYTHON", "python3")
        self.skip_deps = False
        self.assume_yes = False
        self.credentials = {"BOT_TOKEN": "", "API_ID": "", "API_HASH": "", "ADMIN_ID": ""}
        self.failed: list[str] = []
        for item in argv:
            if item.startswith("--prefix="):
                self.prefix = item.split("=", 1)[1]
            elif item.startswith("--env-file="):
                self.env_file = item.split("=", 1)[1]
            elif item.startswith("--state-dir="):
                self.state_dir = item.split("=", 1)[1]
            elif item.startswith("--python="):
                self.python = item.split("=", 1)[1]
            elif item == "--skip-deps":
                self.skip_deps = True
            elif item in ("--yes", "-y"):
                self.assume_yes = True
        self.env_file = self.env_file or "/etc/obhod/obhod.env"

    def tty(self) -> bool:
        if sys.stdin.isatty():
            return True
        try:
            with open("/dev/tty", "r"):
                return True
        except OSError:
            return False

    def ask(self, prompt: str, secret: bool = False, current: str = "") -> str:
        if self.assume_yes and current:
            return current
        if not self.tty():
            raise RuntimeError("there is no terminal for the input, pass --env-file with the keys")
        stream = sys.stdin if sys.stdin.isatty() else open("/dev/tty", "r")
        out = sys.stdout
        out.write("  %s" % prompt)
        out.flush()
        if secret:
            try:
                import termios
                import tty as ttymod
                fd = stream.fileno()
                if not os.isatty(fd):
                    value = stream.readline().strip()
                    return value or current
                old = termios.tcgetattr(fd)
                value = ""
                try:
                    ttymod.setraw(fd)
                    attrs = termios.tcgetattr(fd)
                    attrs[3] = attrs[3] & ~termios.ECHO
                    termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
                    while True:
                        ch = os.read(fd, 1).decode('utf-8', errors='ignore')
                        if ch in ('\n', '\r'):
                            out.write("\n")
                            out.flush()
                            break
                        elif ch == '\x7f' or ch == '\x08':
                            if value:
                                value = value[:-1]
                                out.write("\b \b")
                                out.flush()
                        elif ch == '\x03':
                            raise KeyboardInterrupt
                        elif ch == '\x15':
                            while value:
                                value = value[:-1]
                                out.write("\b \b")
                            out.flush()
                        elif ch:
                            value += ch
                            out.write(ch if len(value) <= 6 else "*")
                            out.flush()
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
                return value or current
            except Exception:
                try:
                    value = stream.readline().strip()
                    return value or current
                except:
                    return current
        else:
            try:
                value = stream.readline().strip()
            except:
                value = ""
            return value or current

    def read_credentials(self) -> bool:
        head("  2. TELEGRAM CREDENTIALS  ")
        existing = self.read_env_file()
        for name in ("BOT_TOKEN", "API_ID", "API_HASH", "ADMIN_ID"):
            self.credentials[name] = existing.get(name, "")
        if any(existing.values()):
            note("existing config at %s - press enter to keep current values" % self.env_file)
            for name in ("BOT_TOKEN", "API_HASH"):
                if existing.get(name):
                    note("current %s: %s" % (name.lower(), mask_secret(name, existing[name])))
            note("current services will be kept (state in %s)" % self.state_dir)
        else:
            note("the token and the hash stay invisible while you type, and never reach the shell history")
        try:
            tok_hint = " [%s]" % mask_secret("BOT_TOKEN", self.credentials["BOT_TOKEN"]) if self.credentials["BOT_TOKEN"] else ""
            self.credentials["BOT_TOKEN"] = self.ask("telegram bot token%s: " % tok_hint, True, self.credentials["BOT_TOKEN"])
            api_hint = " [%s]" % self.credentials["API_ID"] if self.credentials["API_ID"] else ""
            self.credentials["API_ID"] = self.ask("telegram api_id%s: " % api_hint, False, self.credentials["API_ID"])
            hash_hint = " [%s]" % mask_secret("API_HASH", self.credentials["API_HASH"]) if self.credentials["API_HASH"] else ""
            self.credentials["API_HASH"] = self.ask("telegram api_hash%s: " % hash_hint, True, self.credentials["API_HASH"])
            adm_hint = " [%s]" % self.credentials["ADMIN_ID"] if self.credentials["ADMIN_ID"] else ""
            self.credentials["ADMIN_ID"] = self.ask("admin telegram id%s: " % adm_hint, False, self.credentials["ADMIN_ID"])
        except RuntimeError as exc:
            return bool(fail(str(exc)))
        line(INFO, "token: %s, api_id: %s, admin id: %s" % (mask_secret("BOT_TOKEN", self.credentials["BOT_TOKEN"]), self.credentials["API_ID"] or "missing", self.credentials["ADMIN_ID"] or "missing"))
        return self.validate_credentials()

    def validate_credentials(self) -> bool:
        token = self.credentials["BOT_TOKEN"]
        api_id = self.credentials["API_ID"]
        api_hash = self.credentials["API_HASH"]
        admin = self.credentials["ADMIN_ID"]
        if not TOKEN_RE.match(token):
            return bool(fail("the bot token must look like 123456:ABC-DEF, without spaces and brackets"))
        if not api_id.isdigit() or int(api_id) <= 0:
            return bool(fail("api_id must be a positive number"))
        if not HASH_RE.match(api_hash):
            return bool(fail("api_hash must be 32 hex characters"))
        if not admin.isdigit() or int(admin) < 0:
            return bool(fail("admin id must be a number"))
        for name, value in self.credentials.items():
            if any(char in value for char in "\n\r\x00="):
                return bool(fail("%s contains a forbidden character" % name))
        line(OK, "credentials look valid")
        return True

    def read_env_file(self) -> dict[str, str]:
        out: dict[str, str] = {}
        try:
            text = Path(self.env_file).read_text(encoding="utf-8")
        except OSError:
            return out
        for raw in text.splitlines():
            if "=" not in raw or raw.strip().startswith("#"):
                continue
            name, value = raw.split("=", 1)
            out[name.strip()] = value.strip()
        return out

    def write_env_file(self) -> None:
        path = Path(self.env_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        body = ["BOT_TOKEN=" + self.credentials["BOT_TOKEN"], "API_ID=" + self.credentials["API_ID"], "API_HASH=" + self.credentials["API_HASH"], "ADMIN_ID=" + self.credentials["ADMIN_ID"], "OBHOD_STATE_DIR=" + self.state_dir]
        handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write("\n".join(body) + "\n")
        os.chmod(path, 0o600)
        line(OK, "config %s, mode 600" % path)

    def check_python(self) -> bool:
        binary = shutil.which(self.python) or self.python
        try:
            version = subprocess.run([binary, "-c", "import sys; print('%d%02d' % sys.version_info[:2])"], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return bool(fail("%s is not installed" % self.python))
        if version.returncode != 0:
            return bool(fail("%s does not start" % binary))
        if int(version.stdout.strip() or 0) < 313:
            line(WARN, "%s is older than 3.13, goygram needs 3.13 or newer" % binary)
            note("sudo add-apt-repository ppa:deadsnakes/ppa && sudo apt install -y python3.13 python3.13-venv")
            note("repeat with --python=/usr/bin/python3.13")
            return False
        line(OK, "python %s" % binary)
        return True

    def check_network(self) -> bool:
        import urllib.request

        probes = (("github", "https://github.com/"), ("pypi", os.environ.get("PIP_INDEX_URL", "https://pypi.org/simple/") + "goygram/"))
        ok = True
        for name, url in probes:
            started = time.time()
            try:
                with urllib.request.urlopen(url, timeout=15) as response:
                    code = response.status
            except Exception as exc:
                line(WARN, "%s is not reachable: %s" % (name, type(exc).__name__))
                note("the install can stall on this step, check the network or a proxy")
                ok = False
                continue
            line(OK, "%s reachable in %.1fs (%s)" % (name, time.time() - started, code))
        return ok

    def run_installer(self) -> int:
        installer = Path(__file__).resolve().parent / "obhod-install.sh"
        if not installer.is_file():
            return fail("the installer is missing at %s" % installer)
        args = ["bash", str(installer), "install", "--prefix=" + self.prefix, "--env-file=" + self.env_file, "--python=" + self.python, "--yes"]
        if self.skip_deps:
            args.append("--skip-deps")
        head("3. install")
        note(" ".join(shlex.quote(item) for item in args))
        started = time.time()
        env = dict(os.environ)
        env["OBHOD_NO_UI"] = "0" if COLOR else "1"
        process = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        assert process.stdout is not None
        for raw in process.stdout:
            print("  " + raw.rstrip("\n"))
        code = process.wait()
        if code != 0:
            line(BAD, "the installer stopped with code %d after %.0fs" % (code, time.time() - started))
            return code
        line(OK, "installed in %.0fs" % (time.time() - started))
        return 0

    def run(self) -> int:
        head(TITLE)
        if os.geteuid() != 0:
            return fail("the setup needs root, run it with sudo")
        note("telegram control bot over xray, this screen reads the values and then hands over to the installer")
        print()
        print("  prefix  %s" % self.prefix)
        print("  config  %s" % self.env_file)
        print("  state   %s" % self.state_dir)
        head("1. checks")
        with Spinner("checking python...") as sp:
            ok = self.check_python()
            sp.ok("python", "" if not ok else "")
            if not ok:
                return 2
        with Spinner("checking network...") as sp:
            net_ok = self.check_network()
            sp.ok("network", "ok" if net_ok else "limited")
        if not self.read_credentials():
            return 2
        self.write_env_file()
        return self.run_installer()


def main(argv: list[str]) -> int:
    if "--help" in argv or "-h" in argv:
        print("usage: obhod_setup.py [--prefix=PATH] [--env-file=PATH] [--state-dir=PATH] [--python=PATH] [--skip-deps] [--yes]")
        return 0
    try:
        return Setup(argv).run()
    except KeyboardInterrupt:
        print()
        print(paint("cancelled", "38;5;214"))
        return 130


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
