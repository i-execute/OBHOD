import os
import sys
import importlib
import importlib.util
import logging
import asyncio
from abc import ABC

logger = logging.getLogger(__name__)

MODULES_DIR = os.path.join(os.path.dirname(__file__), "Modules")
BOT_DIR = os.path.dirname(__file__)


class BaseModule(ABC):
    name = "BaseModule"
    version = (1, 0, 0)

    async def on_start(self, bot, data_manager):
        pass

    async def on_stop(self):
        pass


def command(func):
    func._is_command = True
    return func


def loop(interval, autostart=True):
    def decorator(func):
        func._is_loop = True
        func._loop_interval = interval
        func._loop_autostart = autostart
        return func
    return decorator


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
            self._modules[module_name] = instance

            if self._bot and self._data_manager:
                await instance.on_start(self._bot, self._data_manager)
                self._start_loops(instance)

            logger.info(f"Loaded module: {module_name}")
            return True, module_name

        except Exception as e:
            logger.error(f"Failed to load module {module_name}: {e}")
            if module_name in sys.modules:
                del sys.modules[module_name]
            return False, str(e)

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
        """Собирает все методы с флагом _is_command со всех загруженных модулей."""
        cmds = {}
        for mod_name, instance in self._modules.items():
            for attr_name in dir(instance):
                method = getattr(instance, attr_name, None)
                if method and callable(method) and getattr(method, "_is_command", False):
                    cmds[attr_name] = method
        return cmds


installer = Installer()
