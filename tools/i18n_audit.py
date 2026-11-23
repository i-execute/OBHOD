from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from BOT import i18n
DYNAMIC_PREFIXES = (
    "CORE_STATE_",
    "DPI_F_",
    "DPI_LEVEL_",
    "FT_CODE_",
    "FT_FW_MODE_",
    "VKCALLS_ERR_",
    "NTF_KIND_",
    "FLD_",
    "FLH_",
    "DBG_",
    "DDOS_",
)
KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")
SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", "dist", "build"}


def py_files() -> list[Path]:
    return [path for path in ROOT.rglob("*.py") if not SKIP_DIRS.intersection(path.parts)]


def referenced_literals() -> tuple[set[str], set[str]]:
    all_constants: set[str] = set()
    translated: set[str] = set()
    for path in py_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value.strip()
                if KEY_RE.fullmatch(value):
                    all_constants.add(value)
            if isinstance(node, ast.Attribute) and KEY_RE.fullmatch(node.attr):
                all_constants.add(node.attr)
            if not path.is_relative_to(ROOT / "BOT") or not isinstance(node, ast.Call) or not node.args:
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
            if name not in {"t", "raw"}:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                value = arg.value.strip()
                if KEY_RE.fullmatch(value):
                    translated.add(value)
    return all_constants, translated


def main() -> int:
    catalogs = [set(i18n.keys(lang)) for lang in i18n.LANGUAGES]
    if any(catalog != catalogs[0] for catalog in catalogs[1:]):
        print("ERROR: translation catalogs do not contain identical key sets")
        return 1
    keys = catalogs[0]
    constants, translated = referenced_literals()
    missing = sorted(translated - keys - set(i18n.RESERVED))
    unused = sorted(keys - constants)
    dynamic = sorted(key for key in unused if key.startswith(DYNAMIC_PREFIXES))
    removal_candidates = sorted(set(unused) - set(dynamic))
    issues = i18n.check_catalogs()
    print("Languages:", ", ".join(i18n.LANGUAGES))
    print("Keys per language:", len(keys))
    print("Catalog/placeholder issues:", len(issues))
    print("Missing statically referenced translation keys:", len(missing))
    for key in missing:
        print("  MISSING", key)
    print("Keys referenced through known dynamic lookup families:", len(dynamic))
    print("Unreferenced keys eligible for removal:", len(removal_candidates))
    for key in removal_candidates:
        print("  UNUSED", key)
    return 1 if issues or missing or removal_candidates else 0


if __name__ == "__main__":
    sys.exit(main())
