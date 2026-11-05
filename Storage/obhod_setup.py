from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

OK = "ok"
BAD = "bad"
WARN = "warn"
INFO = "info"
TITLE = "OBHOD setup"
DEFAULT_PREFIX = "/opt/obhod"
DEFAULT_STATE = "/var/lib/obhod"
DEFAULT_ENV = "/etc/obhod/obhod.env"
MAX_WIDTH = 88
MIN_WIDTH = 44
SECRET_ENV = ("BOT_TOKEN", "API_HASH")
TOKEN_RE = re.compile(r"^[0-9]{5,}:[A-Za-z0-9_-]{30,}$")
HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
ANSI_RE = re.compile("\033\\[[0-9;]*[A-Za-z]")


def glyph(code: str) -> str:
    return chr(int(code, 16))


class g:
    tl = glyph("256d")
    tr = glyph("256e")
    bl = glyph("2570")
    br = glyph("256f")
    h = glyph("2500")
    v = glyph("2502")
    dash = glyph("2504")
    dot_on = glyph("25c6")
    dot_off = glyph("25c7")
    check = glyph("2714")
    cross = glyph("2716")
    tri = glyph("25b2")
    arrow = glyph("276f")
    bullet = glyph("2022")
    bar_on = glyph("2588")
    bar_off = glyph("2591")
    spark = glyph("2726")
    ring = glyph("25cb")
    fill = glyph("25cf")
    up = glyph("2191")
    down = glyph("2193")
    left = glyph("2190")
    right = glyph("2192")
    half = glyph("00b7")


class theme:
    reset = "\033[0m"
    bold = "1"
    dim = "2"
    frame = "38;5;141"
    title = "1;38;5;45"
    accent = "38;5;44"
    good = "38;5;42"
    warn = "38;5;214"
    bad = "38;5;203"
    muted = "38;5;244"
    text = "38;5;252"
    chip = "48;5;236;38;5;252"
    key = "38;5;117"
    cursor = "38;5;213"


def color_enabled() -> bool:
    if os.environ.get("OBHOD_FORCE_COLOR", "") == "1":
        return True
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("OBHOD_NO_UI") == "1":
        return False
    if os.environ.get("TERM", "") in {"dumb", ""} and not os.environ.get("COLORTERM"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


COLOR = color_enabled()


def paint(text: str, *codes: str) -> str:
    if not COLOR or not codes:
        return str(text)
    return "".join("\033[%sm" % code for code in codes) + str(text) + theme.reset


def vlen(text: str) -> int:
    return len(ANSI_RE.sub("", str(text)))


def term_size() -> tuple[int, int]:
    try:
        size = shutil.get_terminal_size(fallback=(88, 26))
        return int(size.columns), int(size.lines)
    except Exception:
        return 88, 26


def width() -> int:
    columns, _rows = term_size()
    return max(MIN_WIDTH, min(columns - 2, MAX_WIDTH))


def clip(text: str, limit: int) -> str:
    plain = ANSI_RE.sub("", str(text))
    if limit <= 1:
        return ""
    if len(plain) <= limit:
        return str(text)
    return plain[: limit - 1] + glyph("2026")


def wrap(text: str, limit: int) -> list[str]:
    words = str(text).split(" ")
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else current + " " + word
        if vlen(candidate) <= limit:
            current = candidate
            continue
        if current:
            lines.append(current)
        plain = ANSI_RE.sub("", word)
        while len(plain) > limit:
            lines.append(plain[:limit])
            plain = plain[limit:]
        current = word if len(plain) == len(ANSI_RE.sub("", word)) else plain
    if current:
        lines.append(current)
    return lines or [""]


def pad(text: str, limit: int) -> str:
    extra = limit - vlen(text)
    return text + " " * max(0, extra)


def mask_secret(name: str, value: str) -> str:
    if not value:
        return "missing"
    if name == "BOT_TOKEN" and ":" in value:
        return value.split(":", 1)[0] + ":****"
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


def write(text: str = "") -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def flush(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()


def frame_top(title: str, limit: int, tone: str = theme.frame) -> str:
    label = clip(title, limit - 6)
    body = g.h + " " + paint(label, theme.title) + " "
    rest = limit - 2 - vlen(body)
    return paint(g.tl, tone) + body + paint(g.h * max(0, rest), tone) + paint(g.tr, tone)


def frame_bottom(limit: int, tone: str = theme.frame) -> str:
    return paint(g.bl + g.h * (limit - 2) + g.br, tone)


def frame_line(body: str, limit: int, tone: str = theme.frame) -> str:
    inner = limit - 4
    cell = pad(clip(body, inner), inner)
    return paint(g.v, tone) + " " + cell + " " + paint(g.v, tone)


def frame_lines(body: str, limit: int, tone: str = theme.frame) -> list[str]:
    return [frame_line(item, limit, tone) for item in wrap(body, limit - 4)]


def panel(title: str, rows: list[str], limit: int = 0, tone: str = theme.frame) -> None:
    limit = limit or width()
    write("")
    write(frame_top(title, limit, tone))
    for row in rows:
        for line in frame_lines(row, limit, tone):
            write(line)
    write(frame_bottom(limit, tone))


def fact(label: str, value: str, note: str = "") -> str:
    tail = paint("  " + note, theme.muted) if note else ""
    return paint(pad(label.strip() + "  ", 14), theme.key) + paint(value, theme.text) + tail


def badge(kind: str) -> str:
    if kind == OK:
        return paint(g.check + " ok", theme.good)
    if kind == WARN:
        return paint(g.tri + " warn", theme.warn)
    if kind == BAD:
        return paint(g.cross + " fail", theme.bad)
    return paint(g.ring + " ..", theme.muted)


def mark(kind: str) -> str:
    if kind == OK:
        return paint(g.check, theme.good)
    if kind == WARN:
        return paint(g.tri, theme.warn)
    if kind == BAD:
        return paint(g.cross, theme.bad)
    return paint(g.ring, theme.muted)


def section(number: int, title: str, rows: list[str], tone: str = theme.frame, note: str = "") -> None:
    limit = width()
    head = paint("%d" % number, theme.muted) + paint(" " + g.half + " ", theme.frame) + paint(title, theme.title)
    if note:
        head += paint("   " + note, theme.muted)
    write("")
    write(frame_top(head, limit, tone))
    for row in rows:
        for line in frame_lines(row, limit, tone):
            write(line)
    write(frame_bottom(limit, tone))


class Spinner:
    def __init__(self, message: str) -> None:
        self.message = message
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.result: tuple[str, str] = (INFO, "")
        self.frames = [glyph("280b"), glyph("2819"), glyph("2839"), glyph("2838"), glyph("283c"), glyph("2834"), glyph("2826"), glyph("2827")]
        self.plain = not COLOR or not has_tty()

    def __enter__(self) -> "Spinner":
        if self.plain:
            return self
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self

    def run(self) -> None:
        index = 0
        while not self.stop.is_set():
            frame = self.frames[index % len(self.frames)]
            flush("\r  " + paint(g.ring, theme.muted) + " " + paint(frame, theme.accent) + " " + self.message + "   ")
            index += 1
            time.sleep(0.09)

    def close(self, kind: str, note: str = "", quiet: bool = False) -> None:
        self.result = (kind, note)
        if quiet:
            if self.thread is not None:
                self.stop.set()
                self.thread.join(timeout=0.4)
                self.thread = None
                flush("\r" + " " * (vlen(self.message) + 10) + "\r")
            return
        if self.thread is not None:
            self.stop.set()
            self.thread.join(timeout=0.4)
            self.thread = None
            flush("\r" + " " * (vlen(self.message) + 8) + "\r")
            write("  " + mark(kind) + " " + pad(paint(self.message, theme.text), 26) + " " + paint(note, theme.muted))
            return
        write("  " + mark(kind) + " " + pad(paint(self.message, theme.text), 26) + " " + paint(note, theme.muted))

    def __exit__(self, *args) -> None:
        if self.thread is not None:
            self.close(OK)


def read_key(stream) -> str:
    import termios
    import tty as ttymod

    fd = stream.fileno()
    old = termios.tcgetattr(fd)
    try:
        ttymod.setraw(fd)
        first = os.read(fd, 1)
        if first in (b"\x03",):
            raise KeyboardInterrupt
        if first in (b"\r", b"\n"):
            return "enter"
        if first == b"\x1b":
            second = os.read(fd, 1)
            if second == b"[":
                third = os.read(fd, 1)
                if third == b"A":
                    return "up"
                if third == b"B":
                    return "down"
                if third == b"C":
                    return "right"
                if third == b"D":
                    return "left"
            return "esc"
        return first.decode("utf-8", errors="ignore")
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def fd_is_tty(fd: int) -> bool:
    try:
        return os.isatty(fd)
    except OSError:
        return False


def has_tty() -> bool:
    if sys.stdin.isatty():
        return True
    try:
        with open("/dev/tty", "r"):
            return True
    except OSError:
        return False


def tty_stream():
    if sys.stdin.isatty():
        return sys.stdin
    try:
        return open("/dev/tty", "r")
    except OSError:
        return None


class Menu:
    def __init__(self, title: str, options: list[str], hint: str = "") -> None:
        self.title = title
        self.options = list(options)
        self.index = 0
        self.hint = hint or "arrows to move, enter to pick, q to cancel"

    def fallback(self, default: int = 0) -> int:
        panel(self.title, [self.hint] + [paint("%d. %s" % (number + 1, item), theme.text) for number, item in enumerate(self.options)])
        stream = tty_stream()
        if stream is None:
            return default
        flush("  " + paint(g.arrow, theme.accent) + " ")
        try:
            raw = stream.readline().strip()
        except Exception:
            return default
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(self.options):
            return int(raw) - 1
        return default

    def ask(self, default: int = 0) -> int:
        stream = tty_stream()
        if stream is None or not COLOR or not has_tty():
            return self.fallback(default)
        fd = stream.fileno()
        if not fd_is_tty(fd):
            return self.fallback(default)
        limit = width()
        write(frame_top(self.title, limit))
        for row in wrap(self.hint, limit - 4):
            write(frame_line(paint(row, theme.muted), limit))
        write(frame_line("", limit))
        for number, option in enumerate(self.options):
            marker = paint(g.dot_on, theme.accent) if number == self.index else paint(g.dot_off, theme.muted)
            label = paint(option, theme.text, theme.bold) if number == self.index else paint(option, theme.muted)
            write(frame_line(marker + " " + label, limit))
        write(frame_bottom(limit))
        while True:
            key = read_key(stream)
            if key in ("up", "k"):
                self.index = (self.index - 1) % len(self.options)
            elif key in ("down", "j"):
                self.index = (self.index + 1) % len(self.options)
            elif key == "enter":
                return self.index
            elif key in ("q", "esc"):
                return -1
            else:
                continue
            flush("\033[%dA" % len(self.options))
            for number, option in enumerate(self.options):
                marker = paint(g.dot_on, theme.accent) if number == self.index else paint(g.dot_off, theme.muted)
                label = paint(option, theme.text, theme.bold) if number == self.index else paint(option, theme.muted)
                write(frame_line(marker + " " + label, limit))


class Field:
    def __init__(self, name: str, label: str, secret: bool = False, default: str = "") -> None:
        self.name = name
        self.label = label
        self.secret = secret
        self.value = default
        self.default = default
        self.error = ""

    def shown(self) -> str:
        if not self.value:
            return paint("empty", theme.muted)
        return mask_secret(self.name, self.value) if self.secret else self.value

    def check(self) -> str:
        if self.name == "BOT_TOKEN" and not TOKEN_RE.match(self.value):
            return "must look like 123456:ABC-DEF"
        if self.name == "API_ID" and not (self.value.isdigit() and int(self.value) > 0):
            return "must be a positive number"
        if self.name == "API_HASH" and not HASH_RE.match(self.value):
            return "must be 32 hex characters"
        if self.name == "ADMIN_ID" and not (self.value.isdigit() and int(self.value) >= 0):
            return "must be a number"
        for char in "\n\r\x00=":
            if char in self.value:
                return "contains a forbidden character"
        return ""


class Setup:
    def __init__(self, argv: list[str]) -> None:
        self.argv = argv
        self.prefix = DEFAULT_PREFIX
        self.state_dir = DEFAULT_STATE
        self.env_file = ""
        self.python = os.environ.get("OBHOD_PYTHON", "python3")
        self.skip_deps = False
        self.assume_yes = False
        self.dry_run = False
        self.credentials = {"BOT_TOKEN": "", "API_ID": "", "API_HASH": "", "ADMIN_ID": ""}
        self.notes: list[str] = []
        self.started = time.time()
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
            elif item in ("--dry-run", "--preview"):
                self.dry_run = True
        self.env_file = self.env_file or DEFAULT_ENV
        self.limit = width()

    def banner(self) -> None:
        limit = self.limit
        write("")
        write(paint("   " + g.spark + " " + "OBHOD" + " " + g.spark, theme.title))
        write(paint("   " + g.h * min(limit - 6, 34), theme.frame))
        write(paint("   telegram control panel for xray", theme.muted) + paint("  " + g.half + "  " + "setup", theme.accent))
        write("")

    def summary_bar(self) -> None:
        rows = [
            fact("target", self.prefix),
            fact("config", self.env_file),
            fact("state ", self.state_dir),
            fact("python", self.python),
        ]
        panel("target server", rows, self.limit)

    def progress(self, done: int, total: int, label: str) -> str:
        total = max(1, total)
        done = max(0, min(done, total))
        cells = 22
        filled = int(round(cells * done / total))
        bar = paint(g.bar_on * filled, theme.accent) + paint(g.bar_off * (cells - filled), theme.muted)
        return "  " + bar + " " + paint("%3d%%" % int(100 * done / total), theme.text) + " " + paint(label, theme.muted)

    def python_binary(self) -> str:
        return shutil.which(self.python) or self.python

    def check_python(self) -> tuple[bool, str]:
        binary = self.python_binary()
        try:
            probe = subprocess.run([binary, "-c", "import sys; print('%d%02d' % sys.version_info[:2])"], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return False, "%s is not installed" % self.python
        if probe.returncode != 0:
            return False, "%s does not start" % binary
        version = probe.stdout.strip() or "0"
        if int(version) < 313:
            self.notes.append("python %s is older than 3.13, install python3.13 and repeat with --python=/usr/bin/python3.13" % binary)
            return False, "%s is too old (%s)" % (binary, version)
        return True, "%s (%s)" % (binary, version)

    def check_network(self) -> tuple[bool, str]:
        import urllib.request

        probes = (("github", "https://github.com/"), ("pypi", os.environ.get("PIP_INDEX_URL", "https://pypi.org/simple/") + "goygram/"))
        good = 0
        started = time.time()
        for name, url in probes:
            try:
                with urllib.request.urlopen(url, timeout=12) as response:
                    response.status
                good += 1
            except Exception as exc:
                self.notes.append("%s is not reachable: %s" % (name, type(exc).__name__))
        elapsed = time.time() - started
        if good == len(probes):
            return True, "github and pypi in %.1fs" % elapsed
        if good:
            return True, "only %d of %d hosts, the install may stall" % (good, len(probes))
        return False, "no network, the install needs github and pypi"

    def check_root(self) -> tuple[bool, str]:
        if self.dry_run:
            return True, "dry run, no changes"
        if os.geteuid() != 0:
            return False, "run the setup with sudo"
        return True, "root"

    def live(self, label: str, probe) -> tuple[bool, str]:
        spin = Spinner(label)
        spin.__enter__()
        try:
            ok, note = probe()
        finally:
            spin.close(OK if ok else BAD, note, quiet=True)
        return ok, note

    def run_checks(self) -> bool:
        results: list[tuple[str, bool, str]] = []
        for label, probe in (("root access", self.check_root), ("python runtime", self.check_python), ("package mirrors", self.check_network)):
            ok, note = self.live(label, probe)
            results.append((label, ok, note))
        rows = []
        hard = True
        for label, ok, note in results:
            kind = OK if ok else (WARN if label == "package mirrors" else BAD)
            if not ok and label != "package mirrors":
                hard = False
            room = max(12, self.limit - 26)
            rows.append(mark(kind) + " " + pad(paint(label, theme.text), 18) + paint(clip(note, room), theme.muted))
        section(1, "checks", rows, theme.good if hard else theme.bad)
        return hard

    def read_env_file(self) -> dict[str, str]:
        values: dict[str, str] = {}
        try:
            text = Path(self.env_file).read_text(encoding="utf-8")
        except OSError:
            return values
        for raw in text.splitlines():
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            name, value = stripped.split("=", 1)
            values[name.strip()] = value.strip().strip('"').strip("'")
        return values

    def read_line(self, prompt: str, current: str = "", secret: bool = False) -> str:
        stream = tty_stream()
        if stream is None:
            raise RuntimeError("there is no terminal for the input, pass --env-file with the keys")
        shown = paint(" [" + mask_secret("BOT_TOKEN" if secret else "PLAIN", current) + "]", theme.muted) if current else ""
        flush("  " + paint(g.arrow, theme.accent) + " " + paint(pad(prompt, 9), theme.key) + shown + " ")
        try:
            import termios

            fd = stream.fileno()
            if not fd_is_tty(fd):
                value = stream.readline().strip()
                return value or current
            old = termios.tcgetattr(fd)
            value = ""
            try:
                attrs = termios.tcgetattr(fd)
                attrs[3] = attrs[3] & ~termios.ECHO
                termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
                while True:
                    char = os.read(fd, 1).decode("utf-8", errors="ignore")
                    if char in ("\n", "\r"):
                        write("")
                        break
                    if char in ("\x7f", "\x08"):
                        if value:
                            value = value[:-1]
                            flush("\b \b")
                        continue
                    if char == "\x03":
                        raise KeyboardInterrupt
                    if char == "\x15":
                        while value:
                            value = value[:-1]
                            flush("\b \b")
                        continue
                    if char and char.isprintable():
                        value += char
                        flush("*" if secret else char)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            return value or current
        except KeyboardInterrupt:
            raise
        except Exception:
            try:
                return stream.readline().strip() or current
            except Exception:
                return current

    def ask_secret(self, prompt: str, current: str = "") -> str:
        if self.assume_yes and current:
            return current
        stream = tty_stream()
        if stream is None:
            raise RuntimeError("there is no terminal for the input, pass --env-file with the keys")
        flush("  " + paint(g.arrow, theme.accent) + " " + prompt + " ")
        try:
            import termios

            fd = stream.fileno()
            if not fd_is_tty(fd):
                value = stream.readline().strip()
                return value or current
            old = termios.tcgetattr(fd)
            value = ""
            try:
                attrs = termios.tcgetattr(fd)
                attrs[3] = attrs[3] & ~termios.ECHO
                termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
                while True:
                    char = os.read(fd, 1).decode("utf-8", errors="ignore")
                    if char in ("\n", "\r"):
                        write("")
                        break
                    if char in ("\x7f", "\x08"):
                        if value:
                            value = value[:-1]
                            flush("\b \b")
                        continue
                    if char == "\x03":
                        raise KeyboardInterrupt
                    if char == "\x15":
                        while value:
                            value = value[:-1]
                            flush("\b \b")
                        continue
                    if char:
                        value += char
                        flush(char if len(value) <= 6 else "*")
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            return value or current
        except KeyboardInterrupt:
            raise
        except Exception:
            try:
                return stream.readline().strip() or current
            except Exception:
                return current

    def ask_plain(self, prompt: str, current: str = "") -> str:
        if self.assume_yes and current:
            return current
        stream = tty_stream()
        if stream is None:
            return current
        shown = paint("[%s]" % current, theme.muted) if current else ""
        flush("  " + paint(g.arrow, theme.accent) + " " + prompt + " " + shown + " ")
        try:
            value = stream.readline().strip()
        except Exception:
            value = ""
        return value or current

    def read_credentials(self) -> bool:
        existing = self.read_env_file()
        for name in ("BOT_TOKEN", "API_ID", "API_HASH", "ADMIN_ID"):
            self.credentials[name] = existing.get(name, "") or self.credentials.get(name, "")
        if self.dry_run and not has_tty():
            self.credentials = {
                "BOT_TOKEN": self.credentials["BOT_TOKEN"] or "123456:AAAA-dry-run-sample-value-000000",
                "API_ID": self.credentials["API_ID"] or "123456",
                "API_HASH": self.credentials["API_HASH"] or "0123456789abcdef0123456789abcdef",
                "ADMIN_ID": self.credentials["ADMIN_ID"] or "777000",
            }
        fields = [
            Field("BOT_TOKEN", "bot token", True, self.credentials["BOT_TOKEN"]),
            Field("API_ID", "api_id", False, self.credentials["API_ID"]),
            Field("API_HASH", "api_hash", True, self.credentials["API_HASH"]),
            Field("ADMIN_ID", "admin id", False, self.credentials["ADMIN_ID"]),
        ]
        rows = [paint("the token and the hash stay hidden while you type and never reach the shell history", theme.muted), ""]
        for field in fields:
            dot = paint(g.fill, theme.accent) if field.value else paint(g.ring, theme.muted)
            rows.append(dot + " " + paint(pad(field.label, 10), theme.key) + " " + field.shown())
        if existing:
            rows.append("")
            rows.append(paint("kept from %s, press enter to leave a value as it is" % self.env_file, theme.muted))
        panel("telegram credentials", rows, self.limit)
        try:
            if not self.assume_yes:
                self.credentials["BOT_TOKEN"] = self.read_line("bot token", self.credentials["BOT_TOKEN"], True)
                self.credentials["API_ID"] = self.read_line("api_id", self.credentials["API_ID"])
                self.credentials["API_HASH"] = self.read_line("api_hash", self.credentials["API_HASH"], True)
                self.credentials["ADMIN_ID"] = self.read_line("admin id", self.credentials["ADMIN_ID"])
        except RuntimeError as exc:
            self.notes.append(str(exc))
            section(2, "credentials", [mark(BAD) + " " + paint(str(exc), theme.bad)], theme.bad)
            return False
        for field in fields:
            field.value = self.credentials[field.name]
            field.error = field.check()
            if field.error:
                self.notes.append("%s: %s" % (field.name.lower(), field.error))
                rows = [mark(BAD) + " " + paint(field.name.lower(), theme.text) + "  " + paint(field.error, theme.bad)]
                section(2, "credentials", rows, theme.bad)
                return False
        rows = [
            mark(OK) + " " + fact("bot token", mask_secret("BOT_TOKEN", self.credentials["BOT_TOKEN"])),
            mark(OK) + " " + fact("api hash ", mask_secret("API_HASH", self.credentials["API_HASH"])),
            mark(OK) + " " + fact("admin id ", self.credentials["ADMIN_ID"] or "missing"),
        ]
        section(2, "credentials", rows, theme.good, "valid")
        return True

    def write_env_file(self) -> bool:
        if self.dry_run:
            return True
        path = Path(self.env_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            body = [
                "BOT_TOKEN=" + self.credentials["BOT_TOKEN"],
                "API_ID=" + self.credentials["API_ID"],
                "API_HASH=" + self.credentials["API_HASH"],
                "ADMIN_ID=" + self.credentials["ADMIN_ID"],
                "OBHOD_STATE_DIR=" + self.state_dir,
            ]
            handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write("\n".join(body) + "\n")
            os.chmod(path, 0o600)
        except OSError as exc:
            self.notes.append("the config %s could not be written: %s" % (path, exc.strerror or exc))
            return False
        return True

    def review(self) -> str:
        rows = [
            fact("prefix  ", self.prefix),
            fact("config  ", self.env_file),
            fact("state   ", self.state_dir),
            fact("python  ", self.python),
            fact("deps    ", "skipped" if self.skip_deps else "installed"),
        ]
        section(3, "plan", rows)
        if self.assume_yes:
            return "go"
        menu = Menu("shall the setup continue", ["install now", "change paths", "cancel"], "arrows to move, enter to pick")
        choice = menu.ask(0)
        if choice == 1:
            self.prefix = self.ask_plain("install directory", self.prefix) or self.prefix
            self.state_dir = self.ask_plain("state directory", self.state_dir) or self.state_dir
            self.env_file = self.ask_plain("config file", self.env_file) or self.env_file
            return self.review()
        if choice != 0:
            return "stop"
        return "go"

    def run_installer(self) -> int:
        installer = Path(__file__).resolve().parent / "obhod-install.sh"
        if not installer.is_file():
            self.notes.append("the installer is missing at %s" % installer)
            section(4, "install", [mark(BAD) + " " + paint("the installer is missing", theme.bad)], theme.bad)
            return 2
        args = ["bash", str(installer), "install", "--prefix=" + self.prefix, "--env-file=" + self.env_file, "--python=" + self.python, "--yes"]
        if self.skip_deps:
            args.append("--skip-deps")
        section(
            4,
            "install",
            [
                paint("command", theme.key),
                paint("  " + clip(" ".join(shlex.quote(item) for item in args), self.limit - 8), theme.muted),
                paint("the output streams below while the installer works", theme.muted),
            ],
        )
        started = time.time()
        env = dict(os.environ)
        env["OBHOD_NO_UI"] = "0" if COLOR else "1"
        env["TERM"] = os.environ.get("TERM", "xterm-256color")
        try:
            process = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        except OSError as exc:
            self.notes.append("the installer did not start: %s" % exc)
            section(4, "install", [mark(BAD) + " " + paint("the installer did not start", theme.bad)], theme.bad)
            return 2
        assert process.stdout is not None
        tail: list[str] = []
        for raw in process.stdout:
            line = raw.rstrip("\n")
            tail.append(line)
            tail = tail[-4:]
            if COLOR:
                flush("\r  " + paint(g.v, theme.frame) + " " + pad(clip(line, self.limit - 6), self.limit - 6))
            else:
                write("  " + line)
        if COLOR:
            flush("\r" + " " * (self.limit - 2) + "\r")
        code = process.wait()
        elapsed = time.time() - started
        if code != 0:
            rows = [mark(BAD) + " " + paint("exit code %d after %.0fs" % (code, elapsed), theme.bad)]
            rows.extend(paint(clip(item, self.limit - 6), theme.muted) for item in tail)
            section(4, "install", rows, theme.bad, "stopped")
            return code
        section(4, "install", [mark(OK) + " " + paint("the installer finished in %.0fs" % elapsed, theme.good)], theme.good, "done")
        return 0

    def run(self) -> int:
        self.banner()
        self.summary_bar()
        write("")
        if not self.run_checks():
            self.finish(2)
            return 2
        if not self.read_credentials():
            self.finish(2)
            return 2
        if not self.write_env_file():
            section(3, "config", [mark(BAD) + " " + paint("the config was not written, look at the notes", theme.bad)], theme.bad)
            self.finish(2)
            return 2
        if not self.dry_run:
            section(3, "config", [mark(OK) + " " + fact("written", self.env_file), mark(OK) + " " + fact("mode   ", "600, owner only")], theme.good)
        action = self.review()
        if action == "stop":
            self.finish(130)
            return 130
        if self.dry_run:
            section(
                4,
                "install",
                [
                    fact("command", "bash Storage/obhod-install.sh install --prefix=" + self.prefix),
                    paint("dry run: nothing was written, the config and the service are untouched", theme.muted),
                ],
                theme.accent,
                "preview",
            )
            self.finish(0)
            return 0
        code = self.run_installer()
        self.finish(code)
        return code

    def finish(self, code: int) -> None:
        elapsed = time.time() - self.started
        if code == 0 and self.dry_run:
            panel(
                "preview finished",
                [
                    paint("nothing was changed on this machine", theme.accent, theme.bold),
                    paint("run the same command without --dry-run to install", theme.muted),
                ],
                self.limit,
                theme.accent,
            )
            return
        if code == 0:
            rows = [
                paint(g.check + " " + "the bot is installed and enabled", theme.good, theme.bold),
                paint("the service restarts itself, the bot answers the owner in telegram", theme.muted),
                paint("next: send /start to the bot, then open the tools screen", theme.muted),
            ]
            panel("done in %.0fs" % elapsed, rows, self.limit, theme.good)
            return
        if code == 130:
            panel("cancelled", [paint("nothing was changed", theme.warn)], self.limit, theme.warn)
            return
        rows = [paint(g.cross + " " + "the setup did not finish", theme.bad, theme.bold)]
        if self.notes:
            rows.append("")
            rows.extend(paint(clip(item, self.limit - 6), theme.muted) for item in self.notes[-5:])
        rows.append("")
        rows.append(paint("fix the points above and run the setup again", theme.muted))
        panel("stopped", rows, self.limit, theme.bad)


def help_text() -> str:
    limit = width()
    rows = [
        paint("usage", theme.key) + "  python3 obhod_setup.py [keys]",
        paint("--prefix", theme.key) + "  " + paint("install directory, default %s" % DEFAULT_PREFIX, theme.text),
        paint("--env-file", theme.key) + "  " + paint("config path, default %s" % DEFAULT_ENV, theme.text),
        paint("--state-dir", theme.key) + "  " + paint("bot state, default %s" % DEFAULT_STATE, theme.text),
        paint("--python", theme.key) + "  " + paint("interpreter, default python3", theme.text),
        paint("--skip-deps", theme.key) + "  " + paint("do not touch system packages", theme.text),
        paint("--yes", theme.key) + "  " + paint("no questions, use the values as they are", theme.text),
        paint("--dry-run", theme.key) + "  " + paint("show the whole screen without changing anything", theme.text),
        paint("env", theme.key) + "  " + paint("OBHOD_NO_UI=1 and NO_COLOR=1 turn the drawing off", theme.text),
    ]
    panel(TITLE, rows, limit)
    return ""


def main(argv: list[str]) -> int:
    if "--help" in argv or "-h" in argv:
        help_text()
        return 0
    try:
        return Setup(argv).run()
    except KeyboardInterrupt:
        write("")
        write(paint("  cancelled", theme.warn))
        return 130
    except Exception as exc:
        write("")
        write(paint("  setup failed: %s: %s" % (type(exc).__name__, exc), theme.bad))
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
