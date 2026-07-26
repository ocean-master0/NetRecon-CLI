import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from netrecon.models import PluginResult, ReconResult, ScanOptions
from netrecon.plugin_base import NetReconPlugin
from netrecon.plugin_registry import PluginRegistry


class EchoPlugin(NetReconPlugin):
    name = "echo"
    description = "Echoes target back into result warnings"
    version = "1.0.0"

    def run(self, options: ScanOptions, result: ReconResult) -> ReconResult:
        result.warnings.append(f"EchoPlugin: target={options.target}")
        return result


class PluginModelTests(unittest.TestCase):
    def test_plugin_result_defaults(self):
        r = PluginResult(plugin_name="test")
        self.assertEqual(r.plugin_name, "test")
        self.assertEqual(r.plugin_version, "0.1.0")
        self.assertEqual(r.data, {})

    def test_plugin_result_to_dict(self):
        r = PluginResult(plugin_name="test", plugin_version="2.0", data={"key": "val"})
        d = r.to_dict()
        self.assertEqual(d["plugin_name"], "test")
        self.assertEqual(d["data"]["key"], "val")


class PluginBaseTests(unittest.TestCase):
    def test_echo_plugin(self):
        plugin = EchoPlugin()
        self.assertEqual(plugin.name, "echo")
        self.assertEqual(plugin.version, "1.0.0")
        result = plugin.run(ScanOptions(target="example.com"), ReconResult(timestamp="t", hostname="h"))
        self.assertIn("EchoPlugin", result.warnings[0])

    def test_to_dict(self):
        plugin = EchoPlugin()
        d = plugin.to_dict()
        self.assertEqual(d["name"], "echo")
        self.assertEqual(d["version"], "1.0.0")


class PluginRegistryTests(unittest.TestCase):
    def test_register_and_get(self):
        registry = PluginRegistry()
        registry.register(EchoPlugin())
        self.assertEqual(registry.count, 1)
        self.assertIsNotNone(registry.get("echo"))
        self.assertIsNone(registry.get("nonexistent"))

    def test_list_plugins(self):
        registry = PluginRegistry()
        registry.register(EchoPlugin())
        plugins = registry.list_plugins()
        self.assertEqual(len(plugins), 1)
        self.assertEqual(plugins[0]["name"], "echo")

    def test_discover_directory(self):
        with TemporaryDirectory() as temp_dir:
            plugin_code = '''
from netrecon.plugin_base import NetReconPlugin
from netrecon.models import ReconResult, ScanOptions

class DirPlugin(NetReconPlugin):
    name = "dirplugin"
    description = "Loaded from directory"
    def run(self, options, result):
        return result
'''
            (Path(temp_dir) / "myplugin.py").write_text(plugin_code, encoding="utf-8")
            registry = PluginRegistry()
            registry.discover_directory(temp_dir)
            self.assertGreater(registry.count, 0)
            self.assertIsNotNone(registry.get("dirplugin"))

    def test_discover_nonexistent_dir(self):
        registry = PluginRegistry()
        # Should not raise
        registry.discover_directory("/nonexistent_path_xyz")
        self.assertEqual(registry.count, 0)

    def test_duplicate_register_overwrites(self):
        registry = PluginRegistry()
        registry.register(EchoPlugin())
        registry.register(EchoPlugin())
        self.assertEqual(registry.count, 1)


if __name__ == "__main__":
    unittest.main()
