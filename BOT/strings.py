import os
import yaml

STRINGS_DIR = os.path.join(os.path.dirname(__file__), "Strings")

LANG_FILES = {
    "en": "English.yml",
    "ru": "Russian.yml",
    "ch": "Chinese.yml",
}

_cache = {}


def _load(lang: str) -> dict:
    if lang in _cache:
        return _cache[lang]
    filename = LANG_FILES.get(lang, LANG_FILES["en"])
    path = os.path.join(STRINGS_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    _cache[lang] = data
    return data


class Strings:
    def __init__(self, lang: str = "en"):
        self.lang = lang
        self._data = _load(lang)

    def set_language(self, lang: str):
        self.lang = lang
        self._data = _load(lang)

    def get(self, key: str, **kwargs) -> str:
        value = self._data.get(key, key)
        if kwargs:
            return value.format(**kwargs)
        return value

    def __getattr__(self, key):
        if key.startswith("_"):
            raise AttributeError(key)
        return self._data.get(key, key)
