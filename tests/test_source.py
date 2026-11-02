from __future__ import annotations

import ast
import io
import pathlib
import tokenize
import unicodedata

ROOT = pathlib.Path(__file__).resolve().parent.parent
AUTHORED_PY = sorted(path for path in ROOT.rglob("*.py") if ".venv" not in path.parts and "__pycache__" not in path.parts)
AUTHORED_SH = sorted(path for path in ROOT.rglob("*.sh") if ".venv" not in path.parts)
TEXT_FILES = AUTHORED_PY + AUTHORED_SH + [
    ROOT / "README.md",
    ROOT / "REPORT.md",
    ROOT / "requirements.txt",
    ROOT / "pytest.ini",
    ROOT / "Storage" / "obhod.service",
]
BANNED_RANGES = (
    (0x1F300, 0x1FAFF),
    (0x1F000, 0x1F2FF),
    (0x2600, 0x27BF),
    (0x2B00, 0x2BFF),
    (0xFE0F, 0xFE0F),
    (0x2190, 0x21FF),
)
BANNED_CHARS = {"\u2014", "\u2013", "\u2015", "\u2500", "\u2550", "\u2551", "\u2588", "\u2714", "\u276f", "\u2022"}
ALLOWED_PUNCT = {"\u00ab", "\u00bb", "\u00b7"}


def test_python_has_no_comments() -> None:
    offenders: list[str] = []
    for path in AUTHORED_PY:
        source = path.read_text(encoding="utf-8")
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                offenders.append(f"{path.relative_to(ROOT)}:{token.start[0]}: {token.string.strip()}")
    assert offenders == []


def test_python_has_no_docstrings() -> None:
    offenders: list[str] = []
    for path in AUTHORED_PY:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = getattr(node, "body", [])
            if not body:
                continue
            first = body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                offenders.append(f"{path.relative_to(ROOT)}:{first.lineno}")
    assert offenders == []


def test_shell_has_only_shebang_hash_lines() -> None:
    offenders: list[str] = []
    for path in AUTHORED_SH:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") and not (number == 1 and stripped.startswith("#!")):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {stripped}")
    assert offenders == []


def test_no_emoji_or_long_dashes() -> None:
    offenders: list[str] = []
    for path in TEXT_FILES:
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for char in line:
                code = ord(char)
                if char in BANNED_CHARS or any(low <= code <= high for low, high in BANNED_RANGES):
                    offenders.append(f"{path.relative_to(ROOT)}:{number}: {hex(code)} {unicodedata.name(char, '?')}")
    assert offenders == []


STRINGS_FILE = ROOT / "BOT" / "strings.py"


def test_text_is_non_ascii_only_in_the_catalog() -> None:
    offenders: list[str] = []
    for path in TEXT_FILES:
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for char in line:
                code = ord(char)
                if code < 128:
                    continue
                if char in ALLOWED_PUNCT:
                    continue
                if path == STRINGS_FILE:
                    continue
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {hex(code)} {unicodedata.name(char, '?')}")
    assert offenders == []


def test_catalog_holds_cyrillic_and_cjk_only() -> None:
    offenders: list[str] = []
    for number, line in enumerate(STRINGS_FILE.read_text(encoding="utf-8").splitlines(), start=1):
        for char in line:
            code = ord(char)
            if code < 128 or char in ALLOWED_PUNCT:
                continue
            if 0x0400 <= code <= 0x04FF:
                continue
            if 0x4E00 <= code <= 0x9FFF:
                continue
            if 0x3000 <= code <= 0x303F:
                continue
            if 0xFF00 <= code <= 0xFFEF:
                continue
            offenders.append(f"{number}: {hex(code)} {unicodedata.name(char, '?')}")
    assert offenders == []


def test_no_shell_script_text_outside_the_catalog() -> None:
    offenders: list[str] = []
    for path in AUTHORED_SH:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for char in line:
                if 0x0400 <= ord(char) <= 0x04FF:
                    offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert offenders == []


def test_no_todo_markers() -> None:
    markers = ("TO" + "DO", "FIX" + "ME", "XX" + "X", "HA" + "CK")
    offenders: list[str] = []
    for path in TEXT_FILES:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker in text:
                offenders.append(f"{path.relative_to(ROOT)}: {marker}")
    assert offenders == []



def test_raise_messages_are_english() -> None:
    offenders: list[str] = []
    for path in AUTHORED_PY:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise):
                continue
            for part in ast.walk(node):
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    for char in part.value:
                        if 0x0400 <= ord(char) <= 0x04FF:
                            offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
                            break
    assert offenders == []


FREE_TURN_FILES = {"freeturn.py", "freeturn_agent.py", "ftpanel.py", "ftscreens.py", "traffic.py"}
FREE_TURN_PREFIXES = ("FT_", "FLD_FT_", "FLH_FT_", "CORE_", "NAV_FREETURN")


def test_no_non_post_quantum_names() -> None:
    banned = ("vmess", "trojan", "shadowsocks", "httpupgrade", "wireguard", "kcp")
    offenders: list[str] = []
    for path in AUTHORED_PY:
        if path.name in {"test_xray.py", "test_screens.py", "test_xscreens.py", "test_source.py", "test_freeturn.py", "test_ftpanel.py", "test_traffic.py"}:
            continue
        if path.name in FREE_TURN_FILES:
            continue
        text = path.read_text(encoding="utf-8")
        if path.name == "strings.py":
            for number, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith(FREE_TURN_PREFIXES):
                    continue
                lowered = stripped.lower()
                for name in banned:
                    if name in lowered:
                        offenders.append(f"{path.relative_to(ROOT)}:{number}: {name}")
            continue
        lowered = text.lower()
        for name in banned:
            if name in lowered:
                offenders.append(f"{path.relative_to(ROOT)}: {name}")
    assert offenders == []
