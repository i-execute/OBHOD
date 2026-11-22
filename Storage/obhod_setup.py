from __future__ import annotations

import atexit
import json
import os
import queue
import re
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

OK = "ok"
BAD = "bad"
WARN = "warn"
INFO = "info"
TITLE = "OBHOD setup"
DEFAULT_PREFIX = "/opt/obhod"
DEFAULT_STATE = "/var/lib/obhod"
DEFAULT_ENV = "/etc/obhod/obhod.env"
MAX_WIDTH = 90
INLINE_WARN_TEXT = "THE BOT IS ALIVE AND WILL BE CONFIGURED, BUT ENABLE INLINE MODE"


def probe_bot_inline(token: str, timeout: float = 5.0) -> tuple[bool, bool | None, str]:
    tok = str(token or "").strip()
    if not tok or ":" not in tok or "dry-run-sample" in tok:
        return False, None, ""
    url = "https://api.telegram.org/bot%s/getMe" % tok
    req = urllib.request.Request(url, headers={"User-Agent": "obhod-setup/2"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read(32768).decode("utf-8", "replace"))
    except Exception:
        return False, None, ""
    if not isinstance(payload, dict) or not payload.get("ok"):
        return False, None, ""
    result = payload.get("result")
    if not isinstance(result, dict):
        return True, None, ""
    uname = str(result.get("username") or "")
    supports = result.get("supports_inline_queries")
    return True, (bool(supports) if isinstance(supports, bool) else None), uname
MIN_WIDTH = 44
ESC_TIMEOUT = 0.15
SEQ_TIMEOUT = 0.25
CRLF_TIMEOUT = 0.015
SECRET_ENV = ("BOT_TOKEN", "API_HASH")
TOKEN_RE = re.compile(r"^[0-9]{5,}:[A-Za-z0-9_-]{30,}$")
HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
ANSI_RE = re.compile("\033\\[[0-9;?]*[A-Za-z]")
SGR_PART_RE = re.compile("(\033\\[[0-9;?]*[A-Za-z])")


def glyph(code: str) -> str:
    return chr(int(code, 16))


class g:
    tl = glyph("256d")
    tr = glyph("256e")
    bl = glyph("2570")
    br = glyph("256f")
    ml = glyph("251c")
    mr = glyph("2524")
    h = glyph("2500")
    v = glyph("2502")
    rail = glyph("2503")
    dash = glyph("2504")
    dot_on = glyph("25c6")
    dot_off = glyph("25c7")
    radio_on = glyph("25c9")
    radio_off = glyph("25cb")
    box_on = glyph("25fc")
    box_off = glyph("25fb")
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
    dots = glyph("2026")


class theme:
    reset = "\033[0m"
    bold = "1"
    dim = "2"
    frame = "38;5;68"
    frame_active = "38;5;111"
    frame_dim = "38;5;239"
    title = "1;38;5;81"
    subtitle = "38;5;153"
    accent = "38;5;45"
    good = "38;5;48"
    warn = "38;5;214"
    bad = "38;5;203"
    muted = "38;5;244"
    subtle = "38;5;240"
    text = "38;5;253"
    bright = "1;38;5;255"
    chip = "48;5;236;38;5;252"
    keycap = "1;48;5;238;38;5;159"
    badge_ok = "1;48;5;22;38;5;120"
    badge_warn = "1;48;5;58;38;5;221"
    badge_bad = "1;48;5;52;38;5;217"
    badge_info = "1;48;5;24;38;5;159"
    row_focus = "48;5;235"
    key = "38;5;117"
    cursor = "1;38;5;45"


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
_SAVED_ATTRS: list[tuple[int, list]] = []
_CURSOR_HIDDEN = False
_RESIZED = False


def _on_winch(_signum: int, _frame: object) -> None:
    global _RESIZED
    _RESIZED = True


def restore_terminal() -> None:
    global _CURSOR_HIDDEN
    try:
        import termios

        while _SAVED_ATTRS:
            fd, attrs = _SAVED_ATTRS.pop()
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
            except OSError:
                pass
    except ImportError:
        _SAVED_ATTRS.clear()
    if _CURSOR_HIDDEN:
        try:
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()
        except Exception:
            pass
        _CURSOR_HIDDEN = False


atexit.register(restore_terminal)


def hide_cursor() -> None:
    global _CURSOR_HIDDEN
    if COLOR and not _CURSOR_HIDDEN:
        _CURSOR_HIDDEN = True
        flush("\033[?25l")


def show_cursor() -> None:
    global _CURSOR_HIDDEN
    if _CURSOR_HIDDEN:
        _CURSOR_HIDDEN = False
        flush("\033[?25h")


def paint(text: str, *codes: str) -> str:
    if not COLOR or not codes:
        return str(text)
    return "".join("\033[%sm" % code for code in codes if code) + str(text) + theme.reset


def keycap(label: str, action: str) -> str:
    if not COLOR:
        return "[%s] %s" % (label, action)
    return paint(" " + label + " ", theme.keycap) + " " + paint(action, theme.muted)


def pill(label: str, style: str = theme.badge_info) -> str:
    if not COLOR:
        return "[%s]" % label
    return paint(" " + label + " ", style)


def vlen(text: str) -> int:
    return len(ANSI_RE.sub("", str(text)))


def term_size() -> tuple[int, int]:
    for candidate in (sys.stdout, sys.stderr, sys.stdin):
        try:
            fd = candidate.fileno()
            if os.isatty(fd):
                sz = os.get_terminal_size(fd)
                return int(sz.columns), int(sz.lines)
        except Exception:
            continue
    try:
        tty_fd = os.open("/dev/tty", os.O_RDONLY | getattr(os, "O_NOCTTY", 0))
        try:
            sz = os.get_terminal_size(tty_fd)
            return int(sz.columns), int(sz.lines)
        finally:
            os.close(tty_fd)
    except Exception:
        pass
    try:
        size = shutil.get_terminal_size(fallback=(88, 28))
        return int(size.columns), int(size.lines)
    except Exception:
        return 88, 28


def width() -> int:
    columns, _rows = term_size()
    return max(MIN_WIDTH, min(columns - 2, MAX_WIDTH))


def clip(text: str, limit: int) -> str:
    raw = str(text)
    if limit <= 0:
        return ""
    plain = ANSI_RE.sub("", raw)
    if len(plain) <= limit:
        return raw
    if limit == 1:
        return g.dots
    target = limit - 1
    parts = SGR_PART_RE.split(raw)
    out: list[str] = []
    seen = 0
    saw_ansi = False
    for part in parts:
        if not part:
            continue
        if SGR_PART_RE.fullmatch(part):
            out.append(part)
            saw_ansi = True
            continue
        remain = target - seen
        if remain <= 0:
            break
        take = part[:remain]
        out.append(take)
        seen += len(take)
        if seen >= target:
            break
    out.append(g.dots)
    if saw_ansi:
        out.append(theme.reset)
    return "".join(out)


def wrap(text: str, limit: int) -> list[str]:
    limit = max(8, limit)
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
        if len(plain) <= limit:
            current = word
            continue
        while len(plain) > limit:
            lines.append(plain[:limit])
            plain = plain[limit:]
        current = plain
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


def frame_top(title: str, limit: int, tone: str = theme.frame, right_note: str = "") -> str:
    right_part = ""
    reserve = 6
    if right_note:
        clipped_right = clip(right_note, max(8, limit // 3))
        right_part = " " + clipped_right + " " + paint(g.h, tone)
        reserve += vlen(right_part)
    label = clip(title, max(6, limit - reserve))
    left_body = paint(g.h, tone) + " " + (label if "\033[" in label else paint(label, theme.title)) + " "
    rest = limit - 2 - vlen(left_body) - vlen(right_part)
    return paint(g.tl, tone) + left_body + paint(g.h * max(0, rest), tone) + right_part + paint(g.tr, tone)


def frame_rule(limit: int, tone: str = theme.frame, dashed: bool = True) -> str:
    fill = g.dash if dashed else g.h
    mid_tone = theme.frame_dim if dashed else tone
    return paint(g.ml, tone) + paint(fill * max(0, limit - 2), mid_tone) + paint(g.mr, tone)


def frame_bottom(limit: int, tone: str = theme.frame) -> str:
    return paint(g.bl + g.h * max(0, limit - 2) + g.br, tone)


def frame_line(body: str, limit: int, tone: str = theme.frame, bg: str = "") -> str:
    inner = max(4, limit - 4)
    clipped = clip(body, inner)
    spaces = " " * max(0, inner - vlen(clipped))
    cell = clipped + spaces
    if bg and COLOR:
        cell = "\033[%sm" % bg + cell.replace(theme.reset, theme.reset + "\033[%sm" % bg) + theme.reset
    return paint(g.v, tone) + " " + cell + " " + paint(g.v, tone)


def frame_lines(body: str, limit: int, tone: str = theme.frame) -> list[str]:
    if body == "":
        return [frame_line("", limit, tone)]
    return [frame_line(item, limit, tone) for item in wrap(body, max(8, limit - 4))]


def panel(title: str, rows: list[str], limit: int = 0, tone: str = theme.frame, right_note: str = "") -> None:
    limit = limit or width()
    out = ["", frame_top(title, limit, tone, right_note), frame_line("", limit, tone)]
    for row in rows:
        out.extend(frame_lines(row, limit, tone))
    out.append(frame_line("", limit, tone))
    out.append(frame_bottom(limit, tone))
    write("\n".join(out))


def fact(label: str, value: str, note: str = "") -> str:
    tail = paint("  " + note, theme.muted) if note else ""
    return paint(pad(label.strip(), 13), theme.key) + " " + paint(value, theme.text) + tail


def badge(kind: str) -> str:
    if kind == OK:
        return pill(g.check + " ok", theme.badge_ok)
    if kind == WARN:
        return pill(g.tri + " warn", theme.badge_warn)
    if kind == BAD:
        return pill(g.cross + " fail", theme.badge_bad)
    return pill(g.ring + " info", theme.badge_info)


def mark(kind: str) -> str:
    if kind == OK:
        return paint(g.check, theme.good, theme.bold)
    if kind == WARN:
        return paint(g.tri, theme.warn, theme.bold)
    if kind == BAD:
        return paint(g.cross, theme.bad, theme.bold)
    return paint(g.ring, theme.muted)


def section(number: int, title: str, rows: list[str], tone: str = theme.frame, note: str = "") -> None:
    limit = width()
    head = paint("%d" % number, theme.accent, theme.bold) + paint(" " + g.half + " ", theme.muted) + paint(title, theme.title)
    right_note = paint(note, theme.muted) if note else ""
    panel(head, rows, limit, tone, right_note)


def fd_is_tty(fd: int) -> bool:
    try:
        return os.isatty(fd)
    except OSError:
        return False


def has_tty() -> bool:
    if sys.stdin.isatty():
        return True
    try:
        fd = os.open("/dev/tty", os.O_RDONLY | getattr(os, "O_NOCTTY", 0))
        os.close(fd)
        return True
    except OSError:
        return False


_SHARED_TTY_FD: int | None = None


def open_tty_fd() -> tuple[int | None, bool]:
    global _SHARED_TTY_FD
    if _SHARED_TTY_FD is not None:
        try:
            if os.isatty(_SHARED_TTY_FD):
                return _SHARED_TTY_FD, False
        except OSError:
            _SHARED_TTY_FD = None
    try:
        fd = os.open("/dev/tty", os.O_RDONLY | getattr(os, "O_NOCTTY", 0))
        if os.isatty(fd):
            _SHARED_TTY_FD = fd
            return fd, False
        os.close(fd)
    except OSError:
        pass
    try:
        if sys.stdin.isatty():
            return sys.stdin.fileno(), False
    except Exception:
        pass
    return None, False


def tty_stream():
    if sys.stdin.isatty():
        return sys.stdin
    try:
        return open("/dev/tty", "rb", buffering=0)
    except OSError:
        return None


class CbreakSession:
    def __init__(self, fd: int, cursor_visible: bool = False) -> None:
        self.fd = fd
        self.cursor_visible = cursor_visible
        self.old: list | None = None

    def __enter__(self) -> "CbreakSession":
        if not fd_is_tty(self.fd):
            return self
        try:
            import termios

            self.old = termios.tcgetattr(self.fd)
            _SAVED_ATTRS.append((self.fd, self.old))
            attrs = termios.tcgetattr(self.fd)
            attrs[0] = attrs[0] & ~(termios.IXON | termios.IXOFF)
            attrs[0] = attrs[0] | termios.ICRNL
            attrs[3] = attrs[3] & ~(termios.ICANON | termios.ECHO | termios.IEXTEN)
            attrs[3] = attrs[3] | termios.ISIG
            attrs[6][termios.VMIN] = 1
            attrs[6][termios.VTIME] = 0
            termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
        except Exception:
            self.old = None
        if self.cursor_visible:
            show_cursor()
        else:
            hide_cursor()
        return self

    def __exit__(self, *args) -> None:
        if self.old is not None:
            try:
                import termios

                termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)
            except Exception:
                pass
            if _SAVED_ATTRS and _SAVED_ATTRS[-1][0] == self.fd:
                _SAVED_ATTRS.pop()
            self.old = None
        show_cursor()


class KeyReader:
    def __init__(self, fd: int, read_fn=None, wait_fn=None) -> None:
        self.fd = fd
        self.buf = bytearray()
        self._custom_io = read_fn is not None or wait_fn is not None
        self._read = read_fn or (lambda n: os.read(self.fd, n))
        self._wait = wait_fn or self._default_wait

    def _default_wait(self, timeout: float) -> bool:
        try:
            ready, _, _ = select.select([self.fd], [], [], max(0.0, timeout))
            return bool(ready)
        except Exception:
            return False

    def _fill(self, timeout: float | None = None) -> bool:
        if timeout is None and not self._custom_io:
            while True:
                if _RESIZED:
                    return False
                if self._wait(0.25):
                    break
        elif timeout is not None and not self._wait(timeout):
            return False
        try:
            chunk = self._read(64)
        except InterruptedError:
            return False
        except OSError:
            return False
        if not chunk:
            return False
        self.buf.extend(chunk)
        return True

    def has_buffered(self) -> bool:
        if self.buf:
            return True
        return self._fill(0.0)

    def _parse_csi(self) -> str:
        idx = 2
        while True:
            while idx < len(self.buf):
                byte = self.buf[idx]
                if 0x40 <= byte <= 7 * 16 + 14:
                    seq = bytes(self.buf[2 : idx + 1])
                    del self.buf[: idx + 1]
                    return self._map_csi(seq)
                if byte < 0x20 or byte > 0x3F:
                    del self.buf[:idx]
                    return "noop"
                idx += 1
            if len(self.buf) > 20 or not self._fill(SEQ_TIMEOUT):
                del self.buf[: min(len(self.buf), max(2, idx))]
                return "noop"

    def _map_csi(self, seq: bytes) -> str:
        if not seq:
            return "noop"
        final = chr(seq[-1])
        params = seq[:-1].decode("ascii", errors="ignore")
        if final == "A":
            return "up"
        if final == "B":
            return "down"
        if final == "C":
            return "right"
        if final == "D":
            return "left"
        if final == "H":
            return "home"
        if final == "F":
            return "end"
        if final == "Z":
            return "shift_tab"
        if final == "~":
            first_num = params.split(";", 1)[0]
            if first_num in ("1", "7"):
                return "home"
            if first_num in ("4", "8"):
                return "end"
            if first_num == "3":
                return "delete"
            if first_num == "5":
                return "pgup"
            if first_num == "6":
                return "pgdn"
        return "noop"

    def _parse_ss3(self) -> str:
        if len(self.buf) < 3 and not self._fill(SEQ_TIMEOUT):
            del self.buf[:2]
            return "noop"
        if len(self.buf) < 3:
            del self.buf[:]
            return "noop"
        final = chr(self.buf[2])
        del self.buf[:3]
        mapping = {"A": "up", "B": "down", "C": "right", "D": "left", "H": "home", "F": "end", "M": "enter"}
        return mapping.get(final, "noop")

    def _parse_utf8(self, first: int) -> str:
        needed = 1
        if (first & 0xE0) == 0xC0:
            needed = 2
        elif (first & 0xF0) == 0xE0:
            needed = 3
        elif (first & 0xF8) == 0xF0:
            needed = 4
        while len(self.buf) < needed:
            if not self._fill(0.05):
                break
        take = min(len(self.buf), needed)
        raw = bytes(self.buf[:take])
        del self.buf[:take]
        return raw.decode("utf-8", errors="ignore") or "noop"

    def read(self) -> str:
        global _RESIZED
        if not self.buf:
            if _RESIZED:
                _RESIZED = False
                return "resize"
            if not self._fill(None):
                if _RESIZED:
                    _RESIZED = False
                    return "resize"
                return "eof"
        first = self.buf[0]
        if first == 0x03:
            del self.buf[:1]
            raise KeyboardInterrupt
        if first == 0x04:
            del self.buf[:1]
            return "eof"
        if first in (0x0D, 0x0A):
            del self.buf[:1]
            if first == 0x0D:
                if self.buf and self.buf[0] == 0x0A:
                    del self.buf[:1]
                elif not self.buf and self._fill(CRLF_TIMEOUT) and self.buf and self.buf[0] == 0x0A:
                    del self.buf[:1]
            return "enter"
        if first == 0x20:
            del self.buf[:1]
            return "space"
        if first == 0x09:
            del self.buf[:1]
            return "tab"
        if first in (0x7F, 0x08):
            del self.buf[:1]
            return "backspace"
        if first == 0x15:
            del self.buf[:1]
            return "ctrl_u"
        if first == 0x17:
            del self.buf[:1]
            return "ctrl_w"
        if first == 0x1B:
            if len(self.buf) == 1:
                self._fill(ESC_TIMEOUT)
            if len(self.buf) == 1:
                del self.buf[:1]
                return "esc"
            if self.buf[1] == 0x1B:
                if len(self.buf) == 2:
                    self._fill(ESC_TIMEOUT)
                if len(self.buf) > 2 and self.buf[2] in (0x5B, 0x4F):
                    del self.buf[:1]
                else:
                    del self.buf[:2]
                    return "esc"
            nxt = self.buf[1]
            if nxt == 0x5B:
                return self._parse_csi()
            if nxt == 0x4F:
                return self._parse_ss3()
            del self.buf[:2]
            return "esc"
        if first < 0x20:
            del self.buf[:1]
            return "noop"
        if first >= 0x80:
            return self._parse_utf8(first)
        del self.buf[:1]
        return chr(first)


def read_key(stream) -> str:
    fd = stream.fileno()
    with CbreakSession(fd, cursor_visible=False):
        return KeyReader(fd).read()


class LiveBox:
    def __init__(self) -> None:
        self.lines_drawn = 0

    def render(self, lines: list[str]) -> None:
        buf: list[str] = []
        if self.lines_drawn > 0:
            if self.lines_drawn > 1:
                buf.append("\r\033[%dA" % (self.lines_drawn - 1))
            else:
                buf.append("\r")
            buf.append("\033[J")
        for idx, line in enumerate(lines):
            if idx > 0:
                buf.append("\n")
            buf.append("\r\033[2K" + line)
        flush("".join(buf))
        self.lines_drawn = len(lines)

    def finalize(self, lines: list[str] | None = None) -> None:
        if lines is not None:
            self.render(lines)
        write("")
        self.lines_drawn = 0


class Spinner:
    def __init__(self, message: str) -> None:
        self.message = message
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.result: tuple[str, str] = (INFO, "")
        self.frames = [
            glyph("280b"),
            glyph("2819"),
            glyph("2839"),
            glyph("2838"),
            glyph("283c"),
            glyph("2834"),
            glyph("2826"),
            glyph("2827"),
        ]
        self.plain = not COLOR or not has_tty()

    def __enter__(self) -> "Spinner":
        if self.plain:
            return self
        hide_cursor()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self

    def run(self) -> None:
        index = 0
        while not self.stop.is_set():
            frame = self.frames[index % len(self.frames)]
            flush("\r  " + paint(frame, theme.accent, theme.bold) + " " + paint(self.message, theme.text) + "   ")
            index += 1
            time.sleep(0.08)

    def close(self, kind: str, note: str = "", quiet: bool = False) -> None:
        self.result = (kind, note)
        if self.thread is not None:
            self.stop.set()
            self.thread.join(timeout=0.4)
            self.thread = None
            flush("\r\033[2K")
        show_cursor()
        if quiet:
            return
        write("  " + mark(kind) + " " + pad(paint(self.message, theme.text), 26) + " " + paint(note, theme.muted))

    def __exit__(self, *args) -> None:
        if self.thread is not None:
            self.close(OK)


def next_interactive_key(reader: KeyReader | None, stream) -> str:
    if reader is not None:
        return reader.read()
    return read_key(stream)


class RadioOption:
    def __init__(self, key: str, label: str, description: str = "", tag: str = "") -> None:
        self.key = key
        self.label = label
        self.description = description
        self.tag = tag


class Menu:
    def __init__(self, title: str, options: list[str] | list[RadioOption], hint: str = "", subtitle: str = "", step_note: str = "") -> None:
        self.title = title
        self.items: list[RadioOption] = [
            opt if isinstance(opt, RadioOption) else RadioOption(str(i), str(opt))
            for i, opt in enumerate(options)
        ]
        self.options = [item.label for item in self.items]
        self.index = 0
        self.selected = 0
        self.subtitle = subtitle
        self.step_note = step_note
        self.hint = hint or "arrows to move, space to select, enter to confirm"

    def fallback(self, default: int = 0) -> int:
        rows = []
        if self.subtitle:
            rows.append(paint(self.subtitle, theme.muted))
        rows.append(paint(self.hint, theme.muted))
        rows.append("")
        for number, item in enumerate(self.items):
            prefix = "*" if number == default else " "
            rows.append(paint("%s %d. %s" % (prefix, number + 1, item.label), theme.text))
        panel(self.title, rows)
        fd, _owned = open_tty_fd()
        if fd is None:
            return default
        flush("  " + paint(g.arrow, theme.accent) + " ")
        buf = bytearray()
        while True:
            try:
                ch = os.read(fd, 1)
            except OSError:
                break
            if not ch or ch in (b"\n", b"\r"):
                write("")
                break
            buf.extend(ch)
        raw = buf.decode("utf-8", errors="ignore").strip()
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(self.items):
            return int(raw) - 1
        return default

    def _draw_lines(self) -> list[str]:
        limit = width()
        tone = theme.frame_active
        lines = [frame_top(self.title, limit, tone, self.step_note)]
        if self.subtitle:
            lines.append(frame_line("", limit, tone))
            for row in wrap(self.subtitle, limit - 6):
                lines.append(frame_line(" " + paint(row, theme.subtitle), limit, tone))
            lines.append(frame_line("", limit, tone))
            lines.append(frame_rule(limit, tone, dashed=True))
        lines.append(frame_line("", limit, tone))
        for number, item in enumerate(self.items):
            focused = number == self.index
            chosen = number == self.selected
            pointer = paint(g.arrow, theme.cursor) if focused else " "
            radio = paint(g.radio_on, theme.good, theme.bold) if chosen else paint(g.radio_off, theme.muted)
            label_style = (theme.bright,) if focused else ((theme.text,) if chosen else (theme.muted,))
            label = paint(item.label, *label_style)
            suffix = ""
            if item.tag:
                tag_style = theme.badge_bad if item.tag == "danger" else (theme.badge_ok if chosen else theme.chip)
                suffix += "  " + pill(item.tag, tag_style)
            if focused and not chosen:
                suffix += "  " + paint("[Space]", theme.accent)
            row_body = pointer + " " + radio + "  " + label + suffix
            lines.append(frame_line(row_body, limit, tone, bg=theme.row_focus if focused else ""))
        current = self.items[self.index] if self.items else None
        if current and current.description:
            lines.append(frame_line("", limit, tone))
            lines.append(frame_rule(limit, tone, dashed=True))
            desc_line = paint(g.rail, theme.accent) + " " + paint(current.description, theme.muted)
            lines.append(frame_line(desc_line, limit, tone))
        lines.append(frame_rule(limit, tone, dashed=False))
        if limit < 64:
            footer = keycap(g.up + g.down, "move") + " " + keycap("Space", "pick") + " " + keycap("Enter", "ok") + " " + keycap("Esc", "quit")
        else:
            footer = (
                keycap(g.up + g.down, "move")
                + "  "
                + keycap("Space", "select")
                + "  "
                + keycap("Enter", "confirm")
                + "  "
                + keycap("Esc", "cancel")
            )
        lines.append(frame_line(footer, limit, tone))
        lines.append(frame_bottom(limit, tone))
        return lines

    def _compact_summary(self, cancelled: bool) -> list[str]:
        limit = width()
        if cancelled:
            tone = theme.warn
            body = mark(WARN) + " " + paint("cancelled by user", theme.warn)
            return [frame_top(self.title, limit, tone, self.step_note), frame_line(body, limit, tone), frame_bottom(limit, tone)]
        chosen = self.items[self.selected]
        tone = theme.frame
        body = mark(OK) + " " + paint(chosen.label, theme.bright)
        if chosen.description:
            body += paint("  " + g.half + "  " + chosen.description, theme.muted)
        return [frame_top(self.title, limit, tone, self.step_note), frame_line(body, limit, tone), frame_bottom(limit, tone)]

    def ask(self, default: int = 0) -> int:
        self.index = max(0, min(default, len(self.items) - 1))
        self.selected = self.index
        stream = tty_stream()
        if stream is None or not COLOR or not has_tty():
            return self.fallback(default)
        fd = stream.fileno()
        if not fd_is_tty(fd):
            return self.fallback(default)
        custom_read = read_key is not _DEFAULT_READ_KEY
        box = LiveBox()
        space_used = False
        with CbreakSession(fd, cursor_visible=False):
            reader = None if custom_read else KeyReader(fd)
            write("")
            box.render(self._draw_lines())
            while True:
                key = next_interactive_key(reader, stream)
                while True:
                    if key in ("up", "k"):
                        self.index = (self.index - 1) % len(self.items)
                    elif key in ("down", "j", "tab"):
                        self.index = (self.index + 1) % len(self.items)
                    elif key == "shift_tab":
                        self.index = (self.index - 1) % len(self.items)
                    elif key in ("home", "pgup"):
                        self.index = 0
                    elif key in ("end", "pgdn"):
                        self.index = len(self.items) - 1
                    elif key == "space":
                        self.selected = self.index
                        space_used = True
                    elif key == "enter":
                        if not space_used:
                            self.selected = self.index
                        box.finalize(self._compact_summary(False))
                        return self.selected
                    elif key in ("q", "esc", "eof"):
                        box.finalize(self._compact_summary(True))
                        return -1
                    elif key.isdigit() and 1 <= int(key) <= len(self.items):
                        self.index = int(key) - 1
                        self.selected = self.index
                        space_used = True
                    if reader is not None and reader.buf:
                        peek = reader.buf[0]
                        if peek == 0x1B or peek in (ord("j"), ord("k")):
                            key = reader.read()
                            continue
                    break
                box.render(self._draw_lines())


class CheckOption:
    def __init__(self, key: str, label: str, description: str, checked: bool = False, badge_text: str = "") -> None:
        self.key = key
        self.label = label
        self.description = description
        self.checked = checked
        self.badge_text = badge_text


class CheckMenu:
    def __init__(self, title: str, options: list[CheckOption], subtitle: str = "", step_note: str = "") -> None:
        self.title = title
        self.items = list(options)
        self.index = 0
        self.subtitle = subtitle
        self.step_note = step_note

    def _draw_lines(self) -> list[str]:
        limit = width()
        tone = theme.frame_active
        lines = [frame_top(self.title, limit, tone, self.step_note)]
        if self.subtitle:
            lines.append(frame_line("", limit, tone))
            for row in wrap(self.subtitle, limit - 6):
                lines.append(frame_line(" " + paint(row, theme.subtitle), limit, tone))
            lines.append(frame_line("", limit, tone))
            lines.append(frame_rule(limit, tone, dashed=True))
        lines.append(frame_line("", limit, tone))
        for idx, item in enumerate(self.items):
            focused = idx == self.index
            pointer = paint(g.arrow, theme.cursor) if focused else " "
            if item.checked:
                box = paint("[" + g.check + "]", theme.good, theme.bold)
            else:
                box = paint("[ ]", theme.muted)
            label = paint(item.label, theme.bright if focused else (theme.text if item.checked else theme.muted))
            tail = "  " + pill(item.badge_text, theme.badge_info if item.checked else theme.chip) if item.badge_text else ""
            lines.append(frame_line(pointer + " " + box + "  " + label + tail, limit, tone, bg=theme.row_focus if focused else ""))
        if self.items:
            cur = self.items[self.index]
            lines.append(frame_line("", limit, tone))
            lines.append(frame_rule(limit, tone, dashed=True))
            lines.append(frame_line(paint(g.rail, theme.accent) + " " + paint(cur.description, theme.muted), limit, tone))
        lines.append(frame_rule(limit, tone, dashed=False))
        if limit < 70:
            footer = keycap(g.up + g.down, "move") + " " + keycap("Space", "flip") + " " + keycap("Enter", "ok") + " " + keycap("Esc", "quit")
        else:
            footer = (
                keycap(g.up + g.down, "move")
                + "  "
                + keycap("Space", "toggle")
                + "  "
                + keycap("a", "all/none")
                + "  "
                + keycap("Enter", "confirm")
                + "  "
                + keycap("Esc", "cancel")
            )
        lines.append(frame_line(footer, limit, tone))
        lines.append(frame_bottom(limit, tone))
        return lines

    def _compact_summary(self, cancelled: bool) -> list[str]:
        limit = width()
        if cancelled:
            return [
                frame_top(self.title, limit, theme.warn, self.step_note),
                frame_line(mark(WARN) + " " + paint("cancelled", theme.warn), limit, theme.warn),
                frame_bottom(limit, theme.warn),
            ]
        picked = [item.label for item in self.items if item.checked]
        summary = ", ".join(picked) if picked else "standard defaults"
        return [
            frame_top(self.title, limit, theme.frame, self.step_note),
            frame_line(mark(OK) + " " + paint(summary, theme.text), limit, theme.frame),
            frame_bottom(limit, theme.frame),
        ]

    def ask(self) -> dict[str, bool] | None:
        stream = tty_stream()
        if stream is None or not COLOR or not has_tty() or not fd_is_tty(stream.fileno()):
            return {item.key: item.checked for item in self.items}
        fd = stream.fileno()
        custom_read = read_key is not _DEFAULT_READ_KEY
        box = LiveBox()
        with CbreakSession(fd, cursor_visible=False):
            reader = None if custom_read else KeyReader(fd)
            write("")
            box.render(self._draw_lines())
            while True:
                key = next_interactive_key(reader, stream)
                if key in ("up", "k"):
                    self.index = (self.index - 1) % len(self.items)
                elif key in ("down", "j", "tab"):
                    self.index = (self.index + 1) % len(self.items)
                elif key == "shift_tab":
                    self.index = (self.index - 1) % len(self.items)
                elif key in ("home", "pgup"):
                    self.index = 0
                elif key in ("end", "pgdn"):
                    self.index = len(self.items) - 1
                elif key == "space" and self.items:
                    self.items[self.index].checked = not self.items[self.index].checked
                elif key == "a" and self.items:
                    target = not all(it.checked for it in self.items)
                    for it in self.items:
                        it.checked = target
                elif key == "enter":
                    box.finalize(self._compact_summary(False))
                    return {item.key: item.checked for item in self.items}
                elif key in ("q", "esc", "eof"):
                    box.finalize(self._compact_summary(True))
                    return None
                box.render(self._draw_lines())


class Field:
    def __init__(self, name: str, label: str, secret: bool = False, default: str = "", hint: str = "", choices: list[str] | None = None) -> None:
        self.name = name
        self.label = label
        self.secret = secret
        self.value = default
        self.default = default
        self.hint = hint
        self.choices = list(choices or [])
        self.error = ""

    def shown(self) -> str:
        if not self.value:
            return paint("not set", theme.muted)
        return paint(mask_secret(self.name, self.value) if self.secret else self.value, theme.text)

    def check(self) -> str:
        if self.name == "BOT_TOKEN" and not TOKEN_RE.match(self.value):
            return "must look like 123456:ABC-DEF"
        if self.name == "API_ID" and not (self.value.isdigit() and int(self.value) > 0):
            return "must be a positive number"
        if self.name == "API_HASH" and not HASH_RE.match(self.value):
            return "must be 32 hex characters"
        if self.name == "ADMIN_ID" and not (self.value.isdigit() and int(self.value) >= 0):
            return "must be a number"
        if self.name in ("PREFIX", "STATE_DIR", "ENV_FILE") and not self.value.strip().startswith("/"):
            return "must be an absolute path starting with /"
        if self.name == "PYTHON" and not self.value.strip():
            return "cannot be empty"
        for char in "\n\r\x00=":
            if char in self.value:
                return "contains a forbidden character"
        return ""


class FieldEditor:
    def __init__(self, title: str, fields: list[Field], subtitle: str = "", step_note: str = "", validate_all: bool = True) -> None:
        self.title = title
        self.fields = list(fields)
        self.subtitle = subtitle
        self.step_note = step_note
        self.validate_all = validate_all
        self.index = 0
        self.editing = False
        self.draft = ""
        self.banner_error = ""

    def _edit_preview(self, field: Field) -> str:
        if not self.draft:
            return paint("_", theme.accent, theme.bold)
        if field.secret:
            visible = self.draft[:6] + ("*" * max(0, len(self.draft) - 6))
            return paint(visible, theme.accent) + paint("_", theme.bright)
        return paint(self.draft, theme.accent) + paint("_", theme.bright)

    def _draw_lines(self) -> list[str]:
        limit = width()
        tone = theme.bad if self.banner_error else theme.frame_active
        lines = [frame_top(self.title, limit, tone, self.step_note)]
        if self.subtitle:
            lines.append(frame_line("", limit, tone))
            for row in wrap(self.subtitle, limit - 6):
                lines.append(frame_line(" " + paint(row, theme.subtitle), limit, tone))
            lines.append(frame_line("", limit, tone))
            lines.append(frame_rule(limit, tone, dashed=True))
        lines.append(frame_line("", limit, tone))
        for idx, field in enumerate(self.fields):
            focused = idx == self.index
            pointer = paint(g.arrow, theme.cursor) if focused else " "
            err = field.check() if field.value else ""
            if self.editing and focused:
                status = paint(g.dot_on, theme.accent)
            elif field.value and not err:
                status = paint(g.check, theme.good, theme.bold)
            elif err or field.error:
                status = paint(g.cross, theme.bad, theme.bold)
            else:
                status = paint(g.ring, theme.muted)
            lbl = paint(pad(field.label, 13), theme.bright if focused else theme.key)
            if self.editing and focused:
                val = self._edit_preview(field)
            else:
                val = field.shown()
                if focused:
                    val += "  " + paint("[Space]" if limit < 62 else "[Space to edit]", theme.accent)
            lines.append(frame_line(pointer + " " + status + " " + lbl + " " + val, limit, tone, bg=theme.row_focus if focused else ""))
        cur = self.fields[self.index]
        lines.append(frame_line("", limit, tone))
        lines.append(frame_rule(limit, tone, dashed=True))
        if self.banner_error:
            lines.append(frame_line(mark(BAD) + " " + paint(self.banner_error, theme.bad), limit, tone))
        elif self.editing:
            edit_hint = "Type or paste value, Enter to save, Esc to revert"
            if cur.choices:
                edit_hint = "Type path, Tab to cycle interpreters, Enter to save"
            lines.append(frame_line(paint(g.rail, theme.accent) + " " + paint(edit_hint, theme.accent), limit, tone))
        elif cur.hint:
            lines.append(frame_line(paint(g.rail, theme.accent) + " " + paint(cur.hint, theme.muted), limit, tone))
        lines.append(frame_rule(limit, tone, dashed=False))
        if self.editing:
            if limit < 64:
                footer = keycap("Enter", "save") + " " + keycap("Ctrl+U", "clear") + " " + keycap("Esc", "back")
            else:
                footer = keycap("Enter", "save field") + "  " + keycap("Ctrl+U", "clear") + "  " + keycap("Esc", "discard")
                if cur.choices:
                    footer = keycap("Tab", "cycle") + "  " + footer
        elif limit < 66:
            footer = keycap(g.up + g.down, "move") + " " + keycap("Space", "edit") + " " + keycap("Enter", "ok") + " " + keycap("Esc", "quit")
        else:
            footer = (
                keycap(g.up + g.down, "move")
                + "  "
                + keycap("Space", "edit")
                + "  "
                + keycap("Enter", "confirm all")
                + "  "
                + keycap("Esc", "cancel")
            )
        lines.append(frame_line(footer, limit, tone))
        lines.append(frame_bottom(limit, tone))
        return lines

    def _compact_summary(self, cancelled: bool) -> list[str]:
        limit = width()
        if cancelled:
            return [
                frame_top(self.title, limit, theme.warn, self.step_note),
                frame_line(mark(WARN) + " " + paint("cancelled", theme.warn), limit, theme.warn),
                frame_bottom(limit, theme.warn),
            ]
        rows = [frame_top(self.title, limit, theme.frame, self.step_note)]
        for field in self.fields:
            rows.append(frame_line(mark(OK) + " " + fact(field.label, ANSI_RE.sub("", field.shown())), limit, theme.frame))
        rows.append(frame_bottom(limit, theme.frame))
        return rows

    def ask(self) -> bool:
        stream = tty_stream()
        if stream is None or not has_tty() or not fd_is_tty(stream.fileno()):
            if not self.validate_all:
                return True
            for field in self.fields:
                field.error = field.check()
                if field.error:
                    return False
            return True
        fd = stream.fileno()
        custom_read = read_key is not _DEFAULT_READ_KEY
        box = LiveBox()
        with CbreakSession(fd, cursor_visible=False):
            reader = None if custom_read else KeyReader(fd)
            write("")
            box.render(self._draw_lines())
            while True:
                key = next_interactive_key(reader, stream)
                cur = self.fields[self.index]
                if self.editing:
                    if key == "enter":
                        if self.draft.strip():
                            cur.value = self.draft.strip()
                        cur.error = cur.check() if self.validate_all else ""
                        self.banner_error = ("%s: %s" % (cur.label, cur.error)) if cur.error else ""
                        self.editing = False
                        hide_cursor()
                    elif key in ("esc", "eof"):
                        self.editing = False
                        self.banner_error = ""
                        hide_cursor()
                    elif key == "backspace":
                        self.draft = self.draft[:-1]
                    elif key == "ctrl_u":
                        self.draft = ""
                    elif key == "ctrl_w":
                        self.draft = self.draft.rstrip()
                        pos = self.draft.rfind(" ")
                        self.draft = self.draft[: pos + 1] if pos >= 0 else ""
                    elif key == "tab" and cur.choices:
                        if self.draft in cur.choices:
                            nxt = (cur.choices.index(self.draft) + 1) % len(cur.choices)
                            self.draft = cur.choices[nxt]
                        else:
                            self.draft = cur.choices[0]
                    elif key == "space":
                        self.draft += " "
                    elif len(key) == 1 and key.isprintable():
                        self.draft += key
                        while reader is not None and reader.buf:
                            nxt_byte = reader.buf[0]
                            if 0x20 <= nxt_byte <= 0x7E:
                                ch = reader.read()
                                if ch == "space":
                                    self.draft += " "
                                elif len(ch) == 1 and ch.isprintable():
                                    self.draft += ch
                                continue
                            break
                    box.render(self._draw_lines())
                    continue
                if key in ("up", "k"):
                    self.index = (self.index - 1) % len(self.fields)
                    self.banner_error = ""
                elif key in ("down", "j", "tab"):
                    self.index = (self.index + 1) % len(self.fields)
                    self.banner_error = ""
                elif key == "shift_tab":
                    self.index = (self.index - 1) % len(self.fields)
                    self.banner_error = ""
                elif key in ("home", "pgup"):
                    self.index = 0
                elif key in ("end", "pgdn"):
                    self.index = len(self.fields) - 1
                elif key == "space":
                    self.editing = True
                    self.draft = "" if cur.secret else cur.value
                    self.banner_error = ""
                    show_cursor()
                elif key == "enter":
                    bad_idx = -1
                    for i, field in enumerate(self.fields):
                        field.error = field.check() if self.validate_all else ""
                        if field.error and bad_idx < 0:
                            bad_idx = i
                    if bad_idx >= 0:
                        self.index = bad_idx
                        target = self.fields[bad_idx]
                        if not target.value:
                            self.editing = True
                            self.draft = ""
                            self.banner_error = "%s is required, type it and press Enter" % target.label
                            show_cursor()
                        else:
                            self.banner_error = "%s: %s" % (target.label, target.error)
                        box.render(self._draw_lines())
                        continue
                    box.finalize(self._compact_summary(False))
                    return True
                elif key in ("q", "esc", "eof"):
                    box.finalize(self._compact_summary(True))
                    return False
                box.render(self._draw_lines())


_DEFAULT_READ_KEY = read_key


def detect_pythons() -> list[str]:
    found: list[str] = []
    env_py = os.environ.get("OBHOD_PYTHON", "").strip()
    for name in (env_py, "python3.14", "python3.13", "python3", sys.executable):
        if not name:
            continue
        resolved = shutil.which(name) or (name if os.path.isfile(name) else "")
        if resolved and resolved not in found:
            found.append(resolved)
    return found or ["python3"]


class Setup:
    def __init__(self) -> None:
        self.action = "install"
        self.service_cmd = "restart"
        self.quick = True
        self.prefix = os.environ.get("OBHOD_PREFIX", DEFAULT_PREFIX)
        self.state_dir = os.environ.get("OBHOD_STATE_DIR", DEFAULT_STATE)
        self.env_file = os.environ.get("OBHOD_ENV_FILE", "") or os.environ.get("OBHOD_ENV", "") or DEFAULT_ENV
        pythons = detect_pythons()
        self.python = pythons[0]
        self.python_choices = pythons
        self.dev = False
        self.skip_deps = False
        self.keep_creds = True
        self.purge_all = False
        self.dry_run = False
        self.credentials = {"BOT_TOKEN": "", "API_ID": "", "API_HASH": "", "ADMIN_ID": ""}
        self.notes: list[str] = []
        self.started = time.time()
        self.limit = width()

    def apply_dev_defaults(self, enabled: bool) -> None:
        home = str(Path.home())
        dev_prefix = home + "/.obhod/app"
        dev_env = home + "/.obhod/etc/obhod.env"
        dev_state = home + "/.obhod/state"
        if enabled:
            if self.prefix == DEFAULT_PREFIX:
                self.prefix = dev_prefix
            if self.env_file == DEFAULT_ENV:
                self.env_file = dev_env
            if self.state_dir == DEFAULT_STATE:
                self.state_dir = dev_state
        else:
            if self.prefix == dev_prefix:
                self.prefix = DEFAULT_PREFIX
            if self.env_file == dev_env:
                self.env_file = DEFAULT_ENV
            if self.state_dir == dev_state:
                self.state_dir = DEFAULT_STATE

    def host_label(self) -> str:
        user = "root" if os.geteuid() == 0 else (os.environ.get("USER") or "user")
        try:
            host = socket.gethostname().split(".")[0] or "server"
        except Exception:
            host = "server"
        return paint(user + "@" + host, theme.muted)

    def probe_xray(self) -> tuple[bool, str]:
        if self.dev:
            return True, "managed in bot (local dev mode)"
        state = ""
        if shutil.which("systemctl"):
            try:
                res = subprocess.run(
                    ["systemctl", "is-active", "xray.service"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                state = (res.stdout or "").strip()
            except (OSError, subprocess.SubprocessError):
                state = ""
        if state == "active":
            return True, "active (/usr/local/bin/xray)"
        if os.path.isfile("/usr/local/bin/xray"):
            return True, "installed (%s, auto-checked on apply)" % (state or "stopped")
        return True, "not installed yet (install in bot)"

    def probe_freeturn(self) -> tuple[bool, str]:
        if self.dev:
            return True, "managed in bot (local dev mode)"
        state = ""
        tun = ""
        if shutil.which("ip"):
            try:
                chk = subprocess.run(
                    ["ip", "link", "show", "ft-wg0"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if chk.returncode == 0:
                    tun = ", ft-wg0 up"
            except (OSError, subprocess.SubprocessError):
                tun = ""
        if shutil.which("systemctl"):
            try:
                res = subprocess.run(
                    ["systemctl", "is-active", "free-turn-proxy.service"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                state = (res.stdout or "").strip()
            except (OSError, subprocess.SubprocessError):
                state = ""
        if state == "active":
            return True, "active (systemd%s)" % tun
        if shutil.which("docker"):
            try:
                dk = subprocess.run(
                    ["docker", "inspect", "-f", "{{.State.Status}}", "free-turn-proxy"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if (dk.stdout or "").strip() == "running":
                    return True, "active (docker%s)" % tun
            except (OSError, subprocess.SubprocessError):
                pass
        if os.path.isdir("/opt/free-turn-proxy") or os.path.isfile("/etc/systemd/system/free-turn-proxy.service"):
            return True, "installed (%s%s, auto-healed)" % (state or "stopped", tun)
        return True, "not installed yet (install in bot)"

    def probe_obhod(self) -> tuple[bool, str]:
        if self.dev:
            if Path(self.prefix, "BOT").is_dir():
                return True, "installed (dev)"
            return True, "not installed"
        state = ""
        if shutil.which("systemctl"):
            try:
                res = subprocess.run(
                    ["systemctl", "is-active", "obhod.service"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                state = (res.stdout or "").strip()
            except (OSError, subprocess.SubprocessError):
                state = ""
        if state == "active":
            return True, "active"
        if Path(self.prefix, "BOT").is_dir() or Path(self.env_file).is_file():
            return True, "installed (%s)" % (state or "stopped")
        return True, "not installed"

    def cores_badge_line(self) -> str:
        _ok_o, o_note = self.probe_obhod()
        _ok_x, x_note = self.probe_xray()
        _ok_f, f_note = self.probe_freeturn()
        o_style = theme.badge_ok if o_note.startswith("active") else (theme.badge_warn if o_note.startswith("installed") else theme.chip)
        x_style = theme.badge_ok if x_note.startswith("active") else (theme.badge_warn if x_note.startswith("installed") else theme.chip)
        f_style = theme.badge_ok if f_note.startswith("active") else (theme.badge_warn if f_note.startswith("installed") else theme.chip)
        o_short = "active" if o_note.startswith("active") else ("installed" if o_note.startswith("installed") else "new")
        x_short = "active" if x_note.startswith("active") else ("installed" if x_note.startswith("installed") else "in-bot")
        f_short = "active" if f_note.startswith("active") else ("installed" if f_note.startswith("installed") else "in-bot")
        return (
            pill("OBHOD: " + o_short, o_style)
            + "  "
            + pill("Xray-core: " + x_short, x_style)
            + "  "
            + pill("FreeTurn: " + f_short, f_style)
        )

    def banner(self) -> None:
        self.limit = width()
        head = paint(g.dot_on, theme.accent) + " " + paint("OBHOD", theme.title) + paint(" " + g.half + " Control Center", theme.subtitle)
        rows = [
            paint("Telegram control panel for Xray-core & FreeTurn", theme.bright),
            self.cores_badge_line(),
            paint("Command: obhod  " + g.half + "  arrows to move, space to select, enter to confirm", theme.muted),
        ]
        panel(head, rows, self.limit, theme.frame, self.host_label())

    def summary_bar(self) -> None:
        self.limit = width()
        flags = []
        if self.dry_run:
            flags.append(pill("DRY RUN", theme.badge_info))
        if self.dev:
            flags.append(pill("DEV", theme.badge_warn))
        if self.skip_deps:
            flags.append(pill("NO DEPS", theme.chip))
        mode_line = " ".join(flags) if flags else pill("SYSTEM", theme.badge_ok)
        rows = [
            fact("mode", mode_line),
            fact("target", self.prefix),
            fact("config", self.env_file),
            fact("state", self.state_dir),
            fact("python", self.python),
        ]
        panel("target server", rows, self.limit, theme.frame)

    def step_bar(self, current: int, total: int, label: str) -> str:
        dots = []
        for idx in range(1, total + 1):
            if idx < current:
                dots.append(paint(g.fill, theme.good))
            elif idx == current:
                dots.append(paint(g.radio_on, theme.accent, theme.bold))
            else:
                dots.append(paint(g.ring, theme.subtle))
        chain = paint(g.h, theme.subtle).join(dots)
        return chain + "  " + paint("step %d/%d" % (current, total), theme.muted) + paint(" " + g.half + " " + label, theme.accent)

    def progress(self, done: int, total: int, label: str) -> str:
        total = max(1, total)
        done = max(0, min(done, total))
        cells = 22
        filled = int(round(cells * done / total))
        bar = paint(g.bar_on * filled, theme.accent) + paint(g.bar_off * (cells - filled), theme.subtle)
        return "  " + bar + " " + paint("%3d%%" % int(100 * done / total), theme.text) + " " + paint(label, theme.muted)

    def ask_action(self) -> bool:
        installed = Path(self.prefix, "BOT").is_dir() or Path(self.env_file).is_file()
        tag_install = "self-heal" if installed else "recommended"
        menu = Menu(
            paint("1", theme.accent, theme.bold) + paint(" " + g.half + " ", theme.muted) + paint("Control Center", theme.title),
            [
                RadioOption("install", "Quick Install / Self-Heal", "One-step install or repair of OBHOD while preserving Xray-core & FreeTurn", tag_install),
                RadioOption("update", "Quick Update & Repair", "Refresh BOT, remote agents, and Python venv while healing Xray-core & FreeTurn", "fast" if installed else ""),
                RadioOption("status", "Health & Status", "Immediately inspect obhod.service, Xray-core, FreeTurn (ft-wg0), config, and venv"),
                RadioOption("service", "Service Control", "Restart, start, stop, or read recent journal logs of obhod.service"),
                RadioOption("custom", "Custom / Advanced Setup", "Configure dry-run preview, ~/.obhod dev mode, custom paths, credentials, or clean rebuild"),
                RadioOption("uninstall", "Uninstall OBHOD Only", "Remove obhod.service and /opt/obhod while keeping Xray-core & FreeTurn intact"),
                RadioOption("nuke", "Full Wipe (Delete Everything)", "Completely remove OBHOD, Xray-core, FreeTurn, configs, keys, state, logs, units, and obhod CLI", "danger"),
            ],
            subtitle="Use Up/Down arrows to move, Space to mark your choice, and Enter to run.",
            step_note=paint("main menu", theme.muted),
        )
        choice = menu.ask(0)
        if choice < 0:
            return False
        picked = menu.items[choice].key
        if picked == "custom":
            self.action = "install"
            self.quick = False
            return True
        self.action = picked
        self.quick = True
        if self.action == "service":
            sub = Menu(
                paint("2", theme.accent, theme.bold) + paint(" " + g.half + " ", theme.muted) + paint("Service Control", theme.title),
                [
                    RadioOption("restart", "Restart service", "Restart obhod.service immediately via systemctl"),
                    RadioOption("start", "Start service", "Start obhod.service if currently stopped"),
                    RadioOption("stop", "Stop service", "Stop obhod.service cleanly"),
                    RadioOption("logs", "Show recent logs", "Print the last 200 lines from journalctl -u obhod.service"),
                ],
                subtitle="Select the service operation with Space and confirm with Enter.",
                step_note=paint("service", theme.muted),
            )
            sub_idx = sub.ask(0)
            if sub_idx < 0:
                return False
            self.service_cmd = sub.items[sub_idx].key
        return True

    def ask_uninstall_mode(self) -> bool:
        sub = Menu(
            paint("2", theme.accent, theme.bold) + paint(" " + g.half + " ", theme.muted) + paint("Uninstall OBHOD Panel", theme.title),
            [
                RadioOption("keep", "Remove OBHOD panel only (keep state & keys)", "Delete obhod.service and /opt/obhod; keep obhod.env, state, Xray-core & FreeTurn", "safe"),
                RadioOption("purge", "Remove OBHOD panel + delete credentials & state", "Also delete obhod.env and /var/lib/obhod (Xray-core & FreeTurn binaries remain)"),
                RadioOption("cancel", "Cancel", "Exit without changing anything"),
            ],
            subtitle="Select how OBHOD should be uninstalled.",
            step_note=paint("uninstall", theme.muted),
        )
        idx = sub.ask(0)
        if idx < 0 or sub.items[idx].key == "cancel":
            return False
        self.purge_all = sub.items[idx].key == "purge"
        return True

    def confirm_nuke(self) -> bool:
        self.limit = width()
        targets = [
            mark(BAD) + " " + paint("OBHOD panel: obhod.service, /opt/obhod, /opt/obhod-src, /etc/obhod, /var/lib/obhod, /var/log/obhod, /usr/local/bin/obhod", theme.text),
            mark(BAD) + " " + paint("Xray-core: xray.service, /usr/local/bin/xray, /usr/local/etc/xray, /usr/local/share/xray, /var/log/xray", theme.text),
            mark(BAD) + " " + paint("FreeTurn: free-turn-proxy, docker container, ft-wg0 tunnel, /opt/free-turn-proxy, sysctl & firewall rules", theme.text),
            mark(BAD) + " " + paint("Security drop-ins: obhod-honeypot, fail2ban obhod jails, 99-obhod.conf sshd drop-in, /root/.goygram", theme.text),
        ]
        panel("full system wipe targets", targets, self.limit, theme.bad, pill("DESTRUCTIVE", theme.badge_bad))
        if not has_tty():
            return False
        sub = Menu(
            paint("!", theme.bad, theme.bold) + paint(" " + g.half + " ", theme.muted) + paint("Confirm Full Wipe", theme.title),
            [
                RadioOption("cancel", "Cancel - keep everything untouched", "Abort immediately without deleting any services, keys, or files", "safe default"),
                RadioOption("wipe", "Yes - wipe OBHOD, Xray-core & FreeTurn completely", "Stop all units and permanently delete every binary, config, key, log, and directory above", "destructive"),
                RadioOption("preview", "Preview wipe command only (dry run)", "Show the exact command that would execute without deleting anything", "dry run"),
            ],
            subtitle="Press Down + Space + Enter to confirm permanent deletion of everything.",
            step_note=paint("danger", theme.bad),
        )
        idx = sub.ask(0)
        if idx < 0 or sub.items[idx].key == "cancel":
            return False
        if sub.items[idx].key == "preview":
            self.dry_run = True
        self.purge_all = True
        return True

    def ask_options(self) -> bool:
        if self.quick or self.action in ("status", "service", "uninstall", "nuke"):
            return True
        options: list[CheckOption] = [
            CheckOption(
                "dry_run",
                "Preview only (dry run)",
                "Run preflight checks and show the exact execution plan without changing any files",
                self.dry_run,
                "safe",
            ),
            CheckOption(
                "dev",
                "Local user layout (~/.obhod)",
                "Install inside $HOME/.obhod without root privileges or systemd unit changes",
                self.dev,
                "no-root",
            ),
            CheckOption(
                "skip_deps",
                "Skip Python dependencies",
                "Copy application files without creating or updating the virtual environment",
                self.skip_deps,
                "offline",
            ),
            CheckOption(
                "reinstall",
                "Clean rebuild (reinstall)",
                "Stop leftover processes and recreate the OBHOD prefix from scratch before installing",
                self.action == "reinstall",
                "clean",
            ),
            CheckOption(
                "keep_creds",
                "Reuse saved credentials automatically",
                "Keep existing BOT_TOKEN, API_ID, API_HASH, and ADMIN_ID when already valid on disk",
                self.keep_creds,
                "fast",
            ),
            CheckOption(
                "purge_all",
                "Purge credentials & state directory",
                "Also wipe obhod.env and the state directory during clean rebuild",
                self.purge_all,
                "destructive",
            ),
        ]
        check = CheckMenu(
            paint("2", theme.accent, theme.bold) + paint(" " + g.half + " ", theme.muted) + paint("Setup Options", theme.title),
            options,
            subtitle="Move with Up/Down arrows, press Space to toggle options on or off, and Enter to confirm.",
            step_note=paint("options", theme.muted),
        )
        picked = check.ask()
        if picked is None:
            return False
        self.dry_run = bool(picked.get("dry_run", False))
        new_dev = bool(picked.get("dev", False))
        if new_dev != self.dev:
            self.dev = new_dev
            self.apply_dev_defaults(new_dev)
        self.skip_deps = bool(picked.get("skip_deps", False))
        self.keep_creds = bool(picked.get("keep_creds", False))
        self.purge_all = bool(picked.get("purge_all", False))
        if picked.get("reinstall", False) or self.purge_all:
            self.action = "reinstall"
        else:
            self.action = "install"
        if self.purge_all:
            self.keep_creds = False
        return True

    def ask_paths(self) -> bool:
        if self.quick or self.action in ("status", "service", "uninstall", "nuke"):
            return True
        fields = [
            Field("PREFIX", "app prefix", False, self.prefix, "Application payload directory (default /opt/obhod)"),
            Field("ENV_FILE", "config file", False, self.env_file, "Secret environment file with mode 0600"),
            Field("STATE_DIR", "state dir", False, self.state_dir, "Persistent Xray, FreeTurn, and bot state directory"),
        ]
        if self.action in ("install", "update", "reinstall"):
            fields.append(
                Field(
                    "PYTHON",
                    "python bin",
                    False,
                    self.python,
                    "Python 3.13+ interpreter used to build the service venv",
                    choices=self.python_choices,
                )
            )
        editor = FieldEditor(
            paint("3", theme.accent, theme.bold) + paint(" " + g.half + " ", theme.muted) + paint("Target Paths & Runtime", theme.title),
            fields,
            subtitle="Press Enter to accept these paths, or highlight any row and press Space to customize it.",
            step_note=paint("step 3", theme.muted),
        )
        if not editor.ask():
            return False
        self.prefix = fields[0].value
        self.env_file = fields[1].value
        self.state_dir = fields[2].value
        if len(fields) > 3:
            self.python = fields[3].value
        return True

    def python_binary(self) -> str:
        return shutil.which(self.python) or self.python

    def check_python(self) -> tuple[bool, str]:
        binary = self.python_binary()
        try:
            probe = subprocess.run(
                [binary, "-c", "import sys; print('%d%02d' % sys.version_info[:2])"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return False, "%s is not installed" % self.python
        if probe.returncode != 0:
            return False, "%s does not start" % binary
        version = probe.stdout.strip() or "0"
        if not version.isdigit() or int(version) < 313:
            self.notes.append("python %s is older than 3.13, install python3.13 and select it in the Paths step" % binary)
            return False, "%s is too old (%s)" % (binary, version)
        return True, "%s (%s.%s)" % (binary, version[:-2], version[-2:])

    def check_network(self) -> tuple[bool, str]:
        if self.skip_deps:
            return True, "skipped (offline option selected)"
        import urllib.request

        probes = (
            ("github", "https://github.com/"),
            ("pypi", os.environ.get("PIP_INDEX_URL", "https://pypi.org/simple/").rstrip("/") + "/goygram/"),
        )
        good = 0
        started = time.time()
        for name, url in probes:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "obhod-setup/2"})
                with urllib.request.urlopen(req, timeout=10) as response:
                    response.status
                good += 1
            except Exception as exc:
                self.notes.append("%s is not reachable: %s" % (name, type(exc).__name__))
        elapsed = time.time() - started
        if good == len(probes):
            return True, "github and pypi in %.1fs" % elapsed
        if good:
            return True, "only %d of %d hosts responded, install may be slow" % (good, len(probes))
        return False, "no network access to github or pypi"

    def check_root(self) -> tuple[bool, str]:
        if self.dry_run:
            return True, "dry run, no root writes"
        if self.dev:
            return True, "local user mode (~/.obhod)"
        if os.geteuid() != 0:
            self.notes.append("system mode requires root privileges, run with sudo or enable Local user layout in step 2")
            return False, "run the setup with sudo"
        return True, "root (uid 0)"

    def live(self, label: str, probe) -> tuple[bool, str]:
        spin = Spinner(label)
        spin.__enter__()
        ok, note = False, ""
        try:
            ok, note = probe()
        finally:
            spin.close(OK if ok else BAD, note, quiet=True)
        return ok, note

    def run_checks(self) -> bool:
        self.limit = width()
        if self.action in ("status", "service"):
            return True
        if self.action in ("uninstall", "nuke"):
            ok, _note = self.check_root()
            return ok
        checks: list[tuple[str, object]] = [("privileges", self.check_root)]
        if self.action in ("install", "update", "reinstall"):
            checks.append(("python runtime", self.check_python))
            checks.append(("package mirrors", self.check_network))
            checks.append(("xray-core", self.probe_xray))
            checks.append(("freeturn", self.probe_freeturn))
        results: list[tuple[str, bool, str]] = []
        for label, probe in checks:
            ok, note = self.live(label, probe)
            results.append((label, ok, note))
        rows = []
        hard = True
        for label, ok, note in results:
            kind = OK if ok else (WARN if label == "package mirrors" else BAD)
            if not ok and label != "package mirrors":
                hard = False
            room = max(14, self.limit - 26)
            rows.append(mark(kind) + " " + pad(paint(label, theme.text), 18) + paint(clip(note, room), theme.muted))
        section(4, "Preflight Checks", rows, theme.good if hard else theme.bad, "passed" if hard else "blocked")
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

    def warn_if_inline_disabled(self, token: str) -> None:
        if self.dry_run:
            return
        alive, supports, uname = probe_bot_inline(token)
        if alive and supports is False:
            handle = ("@" + uname) if uname else "@your_bot"
            red_line = "\033[1;31m" + INLINE_WARN_TEXT + "\033[0m"
            rows = [
                mark(BAD) + " " + paint(INLINE_WARN_TEXT, theme.bad, theme.bold),
                paint("BotFather -> /setinline -> " + handle, theme.warn, theme.bold),
            ]
            panel("inline warning", rows, width(), theme.bad)
            write("  " + red_line)

    def read_credentials(self) -> bool:
        if self.action not in ("install", "reinstall"):
            saved_tok = self.read_env_file().get("BOT_TOKEN", "")
            if saved_tok:
                self.warn_if_inline_disabled(saved_tok)
            return True
        existing = {} if self.purge_all else self.read_env_file()
        for name in ("BOT_TOKEN", "API_ID", "API_HASH", "ADMIN_ID"):
            env_val = os.environ.get(name, "") or os.environ.get("OBHOD_" + name.removeprefix("BOT_"), "")
            self.credentials[name] = existing.get(name, "") or env_val or self.credentials.get(name, "")
        if self.dry_run and not has_tty():
            self.credentials = {
                "BOT_TOKEN": self.credentials["BOT_TOKEN"] or ("123456:" + "A" * 30),
                "API_ID": self.credentials["API_ID"] or "123456",
                "API_HASH": self.credentials["API_HASH"] or ("0" * 32),
                "ADMIN_ID": self.credentials["ADMIN_ID"] or "777000",
            }
        fields = [
            Field("BOT_TOKEN", "bot token", True, self.credentials["BOT_TOKEN"], "Token from @BotFather (format 123456:ABC-DEF...)"),
            Field("API_ID", "api_id", False, self.credentials["API_ID"], "Numeric app api_id from my.telegram.org"),
            Field("API_HASH", "api_hash", True, self.credentials["API_HASH"], "32-character hex api_hash from my.telegram.org"),
            Field("ADMIN_ID", "admin id", False, self.credentials["ADMIN_ID"], "Numeric Telegram user ID of the bot owner"),
        ]
        all_valid = all(not f.check() and bool(f.value) for f in fields)
        if self.keep_creds and all_valid:
            rows = [
                mark(OK) + " " + fact("bot token", mask_secret("BOT_TOKEN", self.credentials["BOT_TOKEN"])),
                mark(OK) + " " + fact("api_id", self.credentials["API_ID"]),
                mark(OK) + " " + fact("api_hash", mask_secret("API_HASH", self.credentials["API_HASH"])),
                mark(OK) + " " + fact("admin id", self.credentials["ADMIN_ID"]),
            ]
            section(5, "Telegram Credentials", rows, theme.good, "reused")
            self.warn_if_inline_disabled(self.credentials["BOT_TOKEN"])
            return True
        if not has_tty() and not all_valid:
            self.notes.append("interactive terminal is required to enter Telegram credentials")
            section(5, "Telegram Credentials", [mark(BAD) + " " + paint("missing valid credentials and no interactive tty", theme.bad)], theme.bad)
            return False
        sub = "Secrets stay masked and never enter shell history. Highlight a row with Up/Down, press Space to type or paste, and Enter when all four are ready."
        editor = FieldEditor(
            paint("5", theme.accent, theme.bold) + paint(" " + g.half + " ", theme.muted) + paint("Telegram Credentials", theme.title),
            fields,
            subtitle=sub,
            step_note=paint("step 5", theme.muted),
            validate_all=True,
        )
        if not editor.ask():
            return False
        for field in fields:
            self.credentials[field.name] = field.value
        self.warn_if_inline_disabled(self.credentials["BOT_TOKEN"])
        return True

    def write_env_file(self) -> bool:
        if self.dry_run or self.action not in ("install", "reinstall"):
            return True
        path = Path(self.env_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            keep: list[str] = []
            if path.is_file() and not self.purge_all:
                managed = {"BOT_TOKEN", "API_ID", "API_HASH", "ADMIN_ID", "OBHOD_STATE_DIR"}
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#") or "=" not in stripped:
                        continue
                    key = stripped.split("=", 1)[0].strip()
                    if key not in managed:
                        keep.append(stripped)
            body = [
                "BOT_TOKEN=" + self.credentials["BOT_TOKEN"],
                "API_ID=" + self.credentials["API_ID"],
                "API_HASH=" + self.credentials["API_HASH"],
                "ADMIN_ID=" + self.credentials["ADMIN_ID"],
                "OBHOD_STATE_DIR=" + self.state_dir,
                *keep,
            ]
            tmp = path.with_suffix(".env.tmp")
            handle = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write("\n".join(body) + "\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError as exc:
            self.notes.append("the config %s could not be written: %s" % (path, exc.strerror or exc))
            return False
        return True

    def installer_argv(self) -> list[str]:
        installer = Path(__file__).resolve().parent / "obhod_install.sh"
        cmd = self.service_cmd if self.action == "service" else self.action
        args = ["bash", str(installer), cmd]
        if self.dev:
            args.append("--dev")
        else:
            args.append("--prefix=" + self.prefix)
            args.append("--env-file=" + self.env_file)
        if self.action in ("install", "update", "reinstall"):
            args.append("--python=" + self.python)
            if self.skip_deps:
                args.append("--skip-deps")
        if self.action in ("install", "reinstall"):
            args.append("--yes")
        if self.purge_all and self.action == "reinstall":
            args.append("--purge-all")
        return args

    def review(self) -> str:
        self.limit = width()
        cmd_label = self.service_cmd if self.action == "service" else self.action
        badges = []
        if self.dry_run:
            badges.append(pill("DRY RUN", theme.badge_info))
        if self.dev:
            badges.append(pill("DEV", theme.badge_warn))
        if self.skip_deps:
            badges.append(pill("SKIP DEPS", theme.chip))
        if self.purge_all:
            badges.append(pill("PURGE ALL", theme.badge_bad))
        rows = [
            fact("action", cmd_label + ("  " + " ".join(badges) if badges else "")),
            fact("prefix", self.prefix),
            fact("config", self.env_file),
        ]
        if self.action != "service":
            rows.append(fact("state", self.state_dir))
        if self.action in ("install", "update", "reinstall"):
            rows.append(fact("python", self.python))
            rows.append(fact("deps", "skipped" if self.skip_deps else "venv + requirements"))
            cores_plan = "wiped (--purge-all)" if self.purge_all else "Xray-core & FreeTurn kept + auto-healed"
            rows.append(fact("cores", cores_plan))
        if self.action in ("install", "reinstall"):
            rows.append(fact("token", mask_secret("BOT_TOKEN", self.credentials["BOT_TOKEN"])))
            rows.append(fact("admin", self.credentials["ADMIN_ID"] or "missing"))
        section(6, "Execution Plan", rows, theme.frame, "review")
        if not has_tty():
            return "go"
        go_label = "Finish preview (no disk changes)" if self.dry_run else ("Run %s now" % cmd_label)
        back_label = "Customize options, paths or credentials" if self.quick else "Adjust options or paths"
        menu = Menu(
            paint("6", theme.accent, theme.bold) + paint(" " + g.half + " ", theme.muted) + paint("Confirm Execution", theme.title),
            [
                RadioOption("go", go_label, "Proceed with the plan shown above", "ready"),
                RadioOption("back", back_label, "Open advanced options, paths, and credentials editor"),
                RadioOption("stop", "Cancel and exit", "Quit immediately without running the installer"),
            ],
            subtitle="Press Enter to confirm, or select another option with Arrows + Space.",
            step_note=paint("confirm", theme.muted),
        )
        choice = menu.ask(0)
        if choice == 1:
            self.quick = False
            return "back"
        if choice != 0:
            return "stop"
        return "go"

    def run_installer(self) -> int:
        self.limit = width()
        installer = Path(__file__).resolve().parent / "obhod_install.sh"
        if not installer.is_file():
            self.notes.append("the installer is missing at %s" % installer)
            section(7, "Execute", [mark(BAD) + " " + paint("the installer script is missing", theme.bad)], theme.bad)
            return 2
        args = self.installer_argv()
        stream_direct = self.action in ("status", "service")
        started = time.time()
        env = dict(os.environ)
        env["OBHOD_NO_UI"] = "0" if COLOR else "1"
        env["OBHOD_STATE_DIR"] = self.state_dir
        env["OBHOD_CALLER_PID"] = str(os.getpid())
        env["TERM"] = os.environ.get("TERM", "xterm-256color")
        is_remove = self.action in ("uninstall", "nuke")
        if self.action == "nuke":
            step_badge = "!"
            run_title = "Removing OBHOD, Xray & FreeTurn"
            done_title = "! " + g.half + " Full Wipe Complete"
            fail_title = "! " + g.half + " Full Wipe Failed"
            sec_title = "Full Wipe"
        elif self.action == "uninstall":
            step_badge = "3"
            run_title = "Uninstalling OBHOD"
            done_title = "3 " + g.half + " Uninstall Complete"
            fail_title = "3 " + g.half + " Uninstall Failed"
            sec_title = "Uninstall"
        else:
            step_badge = "7"
            run_title = "Running Installer"
            done_title = "7 " + g.half + " Execution Complete"
            fail_title = "7 " + g.half + " Installer Failed"
            sec_title = "Execute"
        if stream_direct:
            write("")
            proc = subprocess.run(args, env=env)
            return int(proc.returncode)
        try:
            process = subprocess.Popen(
                args,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            self.notes.append("the installer did not start: %s" % exc)
            section(3 if is_remove else 7, sec_title, [mark(BAD) + " " + paint("the installer did not start", theme.bad)], theme.bad)
            return 2
        assert process.stdout is not None
        tail: list[str] = []
        line_queue: queue.Queue[str | None] = queue.Queue()

        def _reader(stream) -> None:
            try:
                for raw_line in stream:
                    line_queue.put(raw_line)
            finally:
                line_queue.put(None)

        reader = threading.Thread(target=_reader, args=(process.stdout,), daemon=True)
        reader.start()
        box = LiveBox()
        if COLOR and has_tty():
            hide_cursor()
            write("")

        def _render_live() -> None:
            if not (COLOR and has_tty()):
                return
            limit = width()
            elapsed_now = time.time() - started
            badge_color = theme.bad if self.action == "nuke" else theme.accent
            lines = [
                frame_top(
                    paint(step_badge, badge_color, theme.bold) + paint(" " + g.half + " ", theme.muted) + paint(run_title, theme.title),
                    limit,
                    theme.frame_active,
                    paint("%.0fs" % elapsed_now, theme.accent),
                ),
                frame_line("", limit, theme.frame_active),
            ]
            shown = tail if tail else ["starting..."]
            for item in shown:
                lines.append(frame_line(paint(g.rail, theme.accent) + " " + paint(item, theme.muted), limit, theme.frame_active))
            lines.append(frame_line("", limit, theme.frame_active))
            lines.append(frame_bottom(limit, theme.frame_active))
            box.render(lines)

        try:
            _render_live()
            eof = False
            while not eof:
                try:
                    raw = line_queue.get(timeout=0.25)
                except queue.Empty:
                    _render_live()
                    continue
                if raw is None:
                    eof = True
                    break
                clean = ANSI_RE.sub("", raw.rstrip("\r\n")).strip()
                if not clean:
                    continue
                tail.append(clean)
                tail = tail[-6:]
                if COLOR and has_tty():
                    _render_live()
                else:
                    write("  " + clean)
        finally:
            show_cursor()
        reader.join(timeout=1.0)
        code = process.wait()
        if self.action == "uninstall" and self.purge_all and code == 0:
            shutil.rmtree(self.state_dir, ignore_errors=True)
            try:
                os.remove(self.env_file)
            except OSError:
                pass
        elapsed = time.time() - started
        if code != 0:
            rows = [mark(BAD) + " " + paint("exit code %d after %.1fs" % (code, elapsed), theme.bad, theme.bold), ""]
            rows.extend(paint(clip(item, self.limit - 6), theme.muted) for item in tail)
            if COLOR and has_tty():
                box.finalize(
                    [
                        frame_top(fail_title, width(), theme.bad, "exit %d" % code),
                        *[frame_line(r, width(), theme.bad) for r in rows],
                        frame_bottom(width(), theme.bad),
                    ]
                )
            else:
                section(3 if is_remove else 7, sec_title, rows, theme.bad, "stopped")
            return code
        done_msg = mark(OK) + " " + paint("completed in %.1fs" % elapsed, theme.good, theme.bold)
        if COLOR and has_tty():
            box.finalize(
                [
                    frame_top(done_title, width(), theme.good, "ok"),
                    frame_line(done_msg, width(), theme.good),
                    frame_bottom(width(), theme.good),
                ]
            )
        else:
            section(3 if is_remove else 7, sec_title, [done_msg], theme.good, "done")
        return 0

    def run(self) -> int:
        self.banner()
        if not self.ask_action():
            self.finish(130)
            return 130
        if self.action in ("status", "service"):
            if self.action == "service" and not self.run_checks():
                self.finish(2)
                return 2
            code = self.run_installer()
            self.finish(code)
            return code
        if self.action == "uninstall":
            if not self.ask_uninstall_mode():
                self.finish(130)
                return 130
            if not self.run_checks():
                self.finish(2)
                return 2
            code = self.run_installer()
            self.finish(code)
            return code
        if self.action == "nuke":
            if not self.confirm_nuke():
                self.finish(130)
                return 130
            if not self.run_checks():
                self.finish(2)
                return 2
            if self.dry_run:
                cmd_preview = " ".join(shlex.quote(part) for part in self.installer_argv())
                section(
                    7,
                    "Preview Command",
                    [
                        fact("would run", cmd_preview),
                        paint("dry run active: nothing on disk was deleted", theme.muted),
                    ],
                    theme.accent,
                    "dry run",
                )
                self.finish(0)
                return 0
            code = self.run_installer()
            self.finish(code)
            return code
        while True:
            if not self.ask_options():
                self.finish(130)
                return 130
            if not self.ask_paths():
                self.finish(130)
                return 130
            if not self.run_checks():
                self.finish(2)
                return 2
            if not self.read_credentials():
                self.finish(130 if not self.notes else 2)
                return 130 if not self.notes else 2
            decision = self.review()
            if decision == "back":
                continue
            if decision == "stop":
                self.finish(130)
                return 130
            break
        if self.dry_run:
            cmd_preview = " ".join(shlex.quote(part) for part in self.installer_argv())
            section(
                7,
                "Preview Command",
                [
                    fact("would run", cmd_preview),
                    paint("dry run active: no files, credentials, or systemd units were modified", theme.muted),
                ],
                theme.accent,
                "dry run",
            )
            self.finish(0)
            return 0
        if not self.write_env_file():
            section(7, "Config", [mark(BAD) + " " + paint("config file could not be written, see notes below", theme.bad)], theme.bad)
            self.finish(2)
            return 2
        code = self.run_installer()
        self.finish(code)
        return code

    def finish(self, code: int) -> None:
        self.limit = width()
        elapsed = time.time() - self.started
        if code == 0 and self.dry_run:
            panel(
                "preview finished",
                [
                    paint(g.check + " dry run completed with zero changes on disk", theme.accent, theme.bold),
                    paint("run obhod again and leave Preview unchecked to apply", theme.muted),
                ],
                self.limit,
                theme.accent,
            )
            return
        if code == 0:
            if self.action == "nuke":
                rows = [
                    paint(g.check + " Full wipe complete: OBHOD, Xray-core & FreeTurn removed", theme.good, theme.bold),
                    paint("all units, binaries, configs, state directories, logs, and /usr/local/bin/obhod were deleted", theme.muted),
                ]
            elif self.action == "uninstall":
                rows = [
                    paint(g.check + " OBHOD has been removed", theme.good, theme.bold),
                    paint("state and credentials were " + ("deleted" if self.purge_all else "preserved on disk"), theme.muted),
                ]
            elif self.action in ("status", "service"):
                rows = [paint(g.check + " operation finished in %.1fs" % elapsed, theme.good, theme.bold)]
            else:
                rows = [
                    paint(g.check + " OBHOD is installed, verified, and ready", theme.good, theme.bold),
                    paint("open Telegram and send /start to manage Xray-core & FreeTurn", theme.muted),
                    paint("manage in SSH anytime: obhod   |   live logs: journalctl -u obhod -f" if not self.dev else ("manual run: OBHOD_ENV=%s %s/venv/bin/python -m BOT" % (self.env_file, self.prefix)), theme.muted),
                ]
            panel("done in %.1fs" % elapsed, rows, self.limit, theme.good)
            return
        if code == 130:
            panel("cancelled", [paint("setup was cancelled, nothing on the system was modified", theme.warn)], self.limit, theme.warn)
            return
        rows = [paint(g.cross + " setup stopped before completion", theme.bad, theme.bold)]
        if self.notes:
            rows.append("")
            rows.extend(paint(clip(item, self.limit - 6), theme.muted) for item in self.notes[-5:])
        rows.append("")
        rows.append(paint("address the issue above and run obhod (or python3 Storage/obhod_setup.py) again", theme.muted))
        panel("stopped", rows, self.limit, theme.bad)


def reject_flags(argv: list[str]) -> int:
    bad = " ".join(argv[:4])
    rows = [
        mark(BAD) + " " + paint("command-line flags are not supported: " + bad, theme.bad, theme.bold),
        "",
        paint("All setup options, paths, modes, and credentials are configured directly inside the TUI.", theme.text),
        paint("Run without arguments:  obhod   (or python3 Storage/obhod_setup.py)", theme.accent),
        "",
        keycap(g.up + g.down, "move") + "  " + keycap("Space", "select") + "  " + keycap("Enter", "confirm"),
    ]
    panel(TITLE, rows, width(), theme.bad)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        return reject_flags(args)
    prev_winch = None
    try:
        if hasattr(signal, "SIGWINCH"):
            prev_winch = signal.getsignal(signal.SIGWINCH)
            signal.signal(signal.SIGWINCH, _on_winch)
        return Setup().run()
    except KeyboardInterrupt:
        restore_terminal()
        write("")
        panel("cancelled", [paint("interrupted by user, terminal state restored", theme.warn)], width(), theme.warn)
        return 130
    except Exception as exc:
        restore_terminal()
        write("")
        write(paint("  setup failed: %s: %s" % (type(exc).__name__, exc), theme.bad))
        return 2
    finally:
        restore_terminal()
        if prev_winch is not None and hasattr(signal, "SIGWINCH"):
            try:
                signal.signal(signal.SIGWINCH, prev_winch)
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
