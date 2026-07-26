from __future__ import annotations

import hashlib
import importlib
import json
import logging
import pkgutil
from pathlib import Path
from typing import Any

from .plugin_base import NetReconPlugin

LOGGER = logging.getLogger(__name__)


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, NetReconPlugin] = {}

    def register(self, plugin: NetReconPlugin) -> None:
        if plugin.name in self._plugins:
            LOGGER.warning("Plugin '%s' already registered, overwriting.", plugin.name)
        self._plugins[plugin.name] = plugin
        LOGGER.info("Registered plugin: %s v%s", plugin.name, plugin.version)

    def get(self, name: str) -> NetReconPlugin | None:
        return self._plugins.get(name)

    def list_plugins(self) -> list[dict[str, Any]]:
        return [p.to_dict() for p in self._plugins.values()]

    @property
    def count(self) -> int:
        return len(self._plugins)

    def discover_entry_points(self) -> None:
        try:
            from importlib.metadata import entry_points
        except ImportError:
            return
        try:
            for ep in entry_points(group="netrecon.plugins"):
                try:
                    plugin_cls = ep.load()
                    if isinstance(plugin_cls, type) and issubclass(plugin_cls, NetReconPlugin) and plugin_cls is not NetReconPlugin:
                        instance = plugin_cls()
                        self.register(instance)
                except Exception as exc:
                    LOGGER.error("Failed to load plugin '%s': %s", ep.name, exc)
        except Exception as exc:
            LOGGER.debug("No netrecon.plugins entry points found: %s", exc)

    def discover_directory(self, directory: str | Path) -> None:
        path = Path(directory)
        if not path.is_dir():
            LOGGER.warning("Plugin directory '%s' does not exist.", directory)
            return
        manifest_path = path / "manifest.json"
        if not manifest_path.exists():
            LOGGER.error("No plugin manifest found in '%s' — skipping directory.", directory)
            return
        try:
            approved = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.error("Failed to read plugin manifest '%s': %s", manifest_path, exc)
            return
        if not isinstance(approved, dict):
            LOGGER.error("Plugin manifest must be a JSON object (name -> sha256).")
            return
        sys_path_before = list(importlib.import_module("sys").path)
        try:
            importlib.import_module("sys").path.insert(0, str(path))
            for finder, modname, ispkg in pkgutil.iter_modules([str(path)]):
                if modname.startswith("_"):
                    continue
                py_file = path / f"{modname}.py"
                if py_file.exists():
                    sha256 = hashlib.sha256(py_file.read_bytes()).hexdigest()
                    expected = approved.get(py_file.name)
                    if not expected:
                        LOGGER.error("Plugin '%s' not listed in manifest — skipping.", py_file.name)
                        continue
                    if sha256 != expected:
                        LOGGER.error("Plugin '%s' checksum mismatch — skipping.", py_file.name)
                        continue
                try:
                    mod = importlib.import_module(modname)
                    for attr_name in dir(mod):
                        attr = getattr(mod, attr_name)
                        if isinstance(attr, type) and issubclass(attr, NetReconPlugin) and attr is not NetReconPlugin:
                            instance = attr()
                            self.register(instance)
                except Exception as exc:
                    LOGGER.error("Failed to import plugin module '%s': %s", modname, exc)
        finally:
            importlib.import_module("sys").path[:] = sys_path_before
