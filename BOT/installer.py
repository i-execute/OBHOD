import os
import sys
import json
import importlib
import importlib.util
import logging
import asyncio
from abc import ABC

logger = logging.getLogger(__name__)

MODULES_DIR = os.path.join(os.path.dirname(__file__), "Modules")
BOT_DIR = os.path.dirname(__file__)
MUTAL_DB_FILE = os.path.join(BOT_DIR, "mutal_access.json")


class BaseModule(ABC):
    name = "BaseModule"
    version = (1, 0, 0)
    strings_english = {}
    strings_russian = {}
    strings_chinese = {}

    def __init__(self):
        self.strings = self.strings_english

    def set_language(self, lang: str):
        mapping = {
            "en": self.strings_english,
            "ru": self.strings_russian,
            "ch": self.strings_chinese,
        }
        self.strings = mapping.get(lang, self.strings_english)

    async def on_start(self, bot, data_manager):
        pass

    async def on_stop(self):
        pass


def command(func):
    func._is_command = True
    return func


def need_command(name):
    def decorator(func):
        func._is_command = True
        func._command_name = name
        return func
    return decorator


def need_button(label):
    def decorator(func):
        func._is_menu_button = True
        func._button_label = label
        return func
    return decorator


def need_inline_input(prefix, validator=None):
    def decorator(func):
        func._is_inline_input = True
        func._input_prefix = prefix
        func._input_validator = validator
        return func
    return decorator


def loop(interval, autostart=True):
    def decorator(func):
        func._is_loop = True
        func._loop_interval = interval
        func._loop_autostart = autostart
        return func
    return decorator


VERSION_MARKER_FILE = "/home/OBHOD/server_version.txt"


def _read_version_marker():
    if not os.path.exists(VERSION_MARKER_FILE):
        return None
    try:
        with open(VERSION_MARKER_FILE, "r") as f:
            return f.read().strip() or None
    except Exception:
        return None


def mutal_access(repository, module_name):
    def decorator(func):
        async def wrapper(self, *args, **kwargs):
            marker_version = _read_version_marker()
            _write_mutal_access(module_name, repository, core_version=marker_version)
            return await func(self, *args, **kwargs)
        wrapper._is_mutal_access = True
        wrapper._mutal_repository = repository
        wrapper._mutal_module_name = module_name
        return wrapper
    return decorator


def _read_mutal_db():
    if not os.path.exists(MUTAL_DB_FILE):
        return {}
    try:
        with open(MUTAL_DB_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_mutal_access(module_name, repository, core_version=None):
    db = _read_mutal_db()
    entry = db.get(module_name, {})
    entry["module"] = module_name
    entry["repository"] = repository
    if core_version is not None:
        entry["core_version"] = core_version
    elif "core_version" not in entry:
        entry["core_version"] = None
    db[module_name] = entry
    tmp = MUTAL_DB_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, MUTAL_DB_FILE)


def get_mutal_access(module_name):
    return _read_mutal_db().get(module_name)


def set_mutal_core_version(module_name, core_version):
    db = _read_mutal_db()
    if module_name in db:
        db[module_name]["core_version"] = core_version
        tmp = MUTAL_DB_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(db, f, indent=2)
        os.replace(tmp, MUTAL_DB_FILE)


class Installer:
    def __init__(self):
        self._modules = {}
        self._bot = None
        self._data_manager = None
        os.makedirs(MODULES_DIR, exist_ok=True)

    def set_context(self, bot, data_manager):
        self._bot = bot
        self._data_manager = data_manager

    async def load_from_file(self, file_path):
        module_name = os.path.splitext(os.path.basename(file_path))[0]

        if module_name in self._modules:
            await self.unload(module_name)

        if BOT_DIR not in sys.path:
            sys.path.insert(0, BOT_DIR)

        try:
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)

            cls = None
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BaseModule)
                    and attr is not BaseModule
                ):
                    cls = attr
                    break

            if cls is None:
                return False, f"No BaseModule subclass found in {module_name}"

            instance = cls()
            lang = "en"
            if self._data_manager and hasattr(self._data_manager, "get_language"):
                lang = self._data_manager.get_language(self._data_manager.owner_id)
            instance.set_language(lang)
            self._modules[module_name] = instance

            if self._bot and self._data_manager:
                await instance.on_start(self._bot, self._data_manager)
                self._start_loops(instance)
                self._run_mutal_access(instance)

            logger.info(f"Loaded module: {module_name}")
            return True, module_name

        except Exception as e:
            logger.error(f"Failed to load module {module_name}: {e}")
            if module_name in sys.modules:
                del sys.modules[module_name]
            return False, str(e)

    def _run_mutal_access(self, instance):
        for attr_name in dir(instance):
            method = getattr(instance, attr_name, None)
            if method and callable(method) and getattr(method, "_is_mutal_access", False):
                repo = method._mutal_repository
                mod_name = method._mutal_module_name
                _write_mutal_access(mod_name, repo)

    async def unload(self, module_name):
        if module_name not in self._modules:
            return False, "Module not loaded"

        instance = self._modules[module_name]
        await instance.on_stop()

        del self._modules[module_name]
        if module_name in sys.modules:
            del sys.modules[module_name]

        logger.info(f"Unloaded module: {module_name}")
        return True, module_name

    def _start_loops(self, instance):
        for attr_name in dir(instance):
            method = getattr(instance, attr_name, None)
            if method and callable(method) and getattr(method, "_is_loop", False):
                interval = method._loop_interval
                autostart = getattr(method, "_loop_autostart", True)
                if autostart:
                    asyncio.create_task(self._run_loop(method, interval))

    async def _run_loop(self, method, interval):
        while True:
            try:
                await method()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Loop error in {method.__name__}: {e}")
            await asyncio.sleep(interval)

    async def load_all(self):
        if not os.path.isdir(MODULES_DIR):
            return
        for filename in sorted(os.listdir(MODULES_DIR)):
            if filename.endswith(".py") and not filename.startswith("_"):
                file_path = os.path.join(MODULES_DIR, filename)
                success, result = await self.load_from_file(file_path)
                if success:
                    logger.info(f"Auto-loaded: {result}")
                else:
                    logger.error(f"Failed to auto-load {filename}: {result}")

    def get_loaded(self):
        return list(self._modules.keys())

    def save_module_file(self, module_name, content):
        file_path = os.path.join(MODULES_DIR, f"{module_name}.py")
        with open(file_path, "wb") as f:
            f.write(content)
        return file_path

    def get_commands(self):
        cmds = {}
        for mod_name, instance in self._modules.items():
            for attr_name in dir(instance):
                method = getattr(instance, attr_name, None)
                if method and callable(method) and getattr(method, "_is_command", False):
                    name = getattr(method, "_command_name", attr_name)
                    cmds[name] = method
        return cmds

    def get_menu_buttons(self):
        buttons = []
        for mod_name, instance in self._modules.items():
            for attr_name in dir(instance):
                method = getattr(instance, attr_name, None)
                if method and callable(method) and getattr(method, "_is_menu_button", False):
                    buttons.append((method._button_label, method))
        return buttons

    def get_inline_inputs(self):
        inputs = {}
        for mod_name, instance in self._modules.items():
            for attr_name in dir(instance):
                method = getattr(instance, attr_name, None)
                if method and callable(method) and getattr(method, "_is_inline_input", False):
                    inputs[method._input_prefix] = (method, getattr(method, "_input_validator", None))
        return inputs

    def reload_translations(self, lang: str):
        for instance in self._modules.values():
            instance.set_language(lang)


installer = Installer()
