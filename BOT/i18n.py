from __future__ import annotations

import re
from typing import Any

from . import strings

LANGUAGES = ("en", "ru", "zh")
AUTO_LANGUAGES = ("en", "ru")
DEFAULT_LANGUAGE = "en"
PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
CATALOGS = {"en": strings.EN, "ru": strings.RU, "zh": strings.ZH}
RESERVED = frozenset({"LANG_CODE", "LANG_NAME"})


class I18nError(Exception):
    pass


def normalize(language: object) -> str:
    text = str(language or "").strip().lower().replace("_", "-")
    if text in LANGUAGES:
        return text
    base = text.split("-")[0]
    if base in LANGUAGES:
        return base
    return DEFAULT_LANGUAGE


def detect_user_language(language: object) -> str:
    text = str(language or "").strip().lower().replace("_", "-")
    base = text.split("-")[0]
    if base in AUTO_LANGUAGES:
        return base
    return DEFAULT_LANGUAGE


def catalog(language: str = DEFAULT_LANGUAGE) -> Any:
    return CATALOGS[normalize(language)]


def keys(language: str = DEFAULT_LANGUAGE) -> list[str]:
    found = []
    for name in dir(catalog(language)):
        if name.startswith("_") or name in RESERVED:
            continue
        if not name.isupper():
            continue
        found.append(name)
    return sorted(found)


def placeholders(text: str) -> set[str]:
    return set(PLACEHOLDER.findall(text or ""))


def has_key(key: str, language: str = DEFAULT_LANGUAGE) -> bool:
    return key in keys(language)


def raw(key: str, language: str = DEFAULT_LANGUAGE) -> str:
    name = str(key or "").strip()
    if not name:
        raise I18nError("a string key is required")
    for candidate in (normalize(language), DEFAULT_LANGUAGE):
        value = getattr(CATALOGS[candidate], name, None)
        if isinstance(value, str):
            return value
    raise I18nError("the string key %s is missing in every catalog" % name)


def t(key: str, language: str = DEFAULT_LANGUAGE, **values: Any) -> str:
    template = raw(key, language)
    if not values:
        return template
    expected = placeholders(template)
    missing = sorted(name for name in expected if name not in values)
    if missing:
        raise I18nError("the string key %s needs the values %s" % (key, ", ".join(missing)))
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError) as exc:
        raise I18nError("the string key %s could not be formatted: %s" % (key, exc)) from None


class Translator:
    def __init__(self, language: str = DEFAULT_LANGUAGE) -> None:
        self.language = normalize(language)

    def __call__(self, key: str, **values: Any) -> str:
        return t(key, self.language, **values)

    def raw(self, key: str) -> str:
        return raw(key, self.language)

    def language_name(self) -> str:
        return raw("LANG_NAME", self.language)

    def change(self, language: str) -> "Translator":
        self.language = normalize(language)
        return self


def translator(language: object = DEFAULT_LANGUAGE) -> Translator:
    return Translator(normalize(language))


def language_names() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for code in LANGUAGES:
        out.append((code, raw("LANG_NAME", code)))
    return out


def check_catalogs() -> list[str]:
    issues: list[str] = []
    base = set(keys(DEFAULT_LANGUAGE))
    for code in LANGUAGES:
        current = set(keys(code))
        for name in sorted(base - current):
            issues.append("%s: missing %s" % (code, name))
        for name in sorted(current - base):
            issues.append("%s: extra %s" % (code, name))
        for name in sorted(current & base):
            reference = placeholders(raw(name, DEFAULT_LANGUAGE))
            actual = placeholders(raw(name, code))
            if reference != actual:
                issues.append("%s: placeholders differ in %s" % (code, name))
            if not raw(name, code).strip():
                issues.append("%s: empty value in %s" % (code, name))
    return issues
