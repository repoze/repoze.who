import importlib
import pathlib
import shutil
import sys
import tempfile
import unittest


class NamespaceCompatibilityTests(unittest.TestCase):

    def _create_pkgutil_sibling(self):
        workspace = pathlib.Path(tempfile.mkdtemp())
        sibling_root = workspace / "sibling"
        plugin_pkg = sibling_root / "repoze" / "who" / "plugins"
        plugin_pkg.mkdir(parents=True)

        ns_init = (
            "from pkgutil import extend_path\n"
            "__path__ = extend_path(__path__, __name__)\n"
        )
        (sibling_root / "repoze" / "__init__.py").write_text(ns_init, encoding="utf-8")
        (sibling_root / "repoze" / "who" / "__init__.py").write_text(
            ns_init, encoding="utf-8"
        )
        (plugin_pkg / "__init__.py").write_text(ns_init, encoding="utf-8")
        (plugin_pkg / "legacy_plugin.py").write_text(
            "class LegacyPlugin:\n    pass\n", encoding="utf-8"
        )
        return workspace, sibling_root

    def _clear_repoze_modules(self):
        for module_name in list(sys.modules):
            if module_name == "repoze" or module_name.startswith("repoze."):
                del sys.modules[module_name]

    def test_plugins_namespace_with_pkgutil_sibling_package(self):
        workspace, sibling_root = self._create_pkgutil_sibling()

        original_sys_path = list(sys.path)
        original_modules = {
            k: v for k, v in sys.modules.items() if k == "repoze" or k.startswith("repoze.")
        }
        self._clear_repoze_modules()

        try:
            sys.path.insert(0, str(sibling_root))
            import repoze.who.plugins

            legacy = importlib.import_module("repoze.who.plugins.legacy_plugin")
            self.assertTrue(hasattr(legacy, "LegacyPlugin"))
            self.assertIn(
                str(sibling_root / "repoze" / "who" / "plugins"),
                [str(path) for path in repoze.who.plugins.__path__],
            )
        finally:
            sys.path[:] = original_sys_path
            self._clear_repoze_modules()
            sys.modules.update(original_modules)
            shutil.rmtree(str(workspace))
