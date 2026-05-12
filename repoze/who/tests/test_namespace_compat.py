import pathlib
import shutil
import sys
import tempfile
import unittest


class NamespaceCompatibilityTests(unittest.TestCase):

    def _create_sibling(self):
        workspace = pathlib.Path(tempfile.mkdtemp())
        sibling_root = workspace / "sibling"
        plugin_pkg = sibling_root / "repoze" / "who" / "plugins"
        plugin_pkg.mkdir(parents=True)

        (plugin_pkg / "sibling_identifier.py").write_text(
            "from zope.interface import implementer\n"
            "from repoze.who.interfaces import IIdentifier\n"
            "\n"
            "@implementer(IIdentifier)\n"
            "class SiblingIdentifier:\n"
            "    def __init__(self, marker=None):\n"
            "        self.marker = marker\n"
            "\n"
            "    def identify(self, environ):\n"
            "        return None\n"
            "\n"
            "    def remember(self, environ, identity):\n"
            "        return []\n"
            "\n"
            "    def forget(self, environ, identity):\n"
            "        return []\n"
            "\n"
            "def make_plugin(marker=None):\n"
            "    return SiblingIdentifier(marker)\n",
            encoding="utf-8",
        )
        return workspace, sibling_root

    def _assert_native_namespace(self, module):
        self.assertIsNone(module.__spec__.origin)
        self.assertIsNotNone(module.__spec__.submodule_search_locations)

    def _clear_repoze_modules(self):
        for module_name in list(sys.modules):
            if module_name == "repoze" or module_name.startswith("repoze."):
                del sys.modules[module_name]

    def test_config_resolves_plugin_from_sibling_namespace_package(self):
        workspace, sibling_root = self._create_sibling()

        original_sys_path = list(sys.path)
        original_modules = {
            k: v
            for k, v in sys.modules.items()
            if k == "repoze" or k.startswith("repoze.")
        }
        self._clear_repoze_modules()

        try:
            sys.path.insert(0, str(sibling_root))
            import repoze
            import repoze.who
            import repoze.who.plugins
            from repoze.who.config import WhoConfig

            self._assert_native_namespace(repoze)
            self._assert_native_namespace(repoze.who)
            self._assert_native_namespace(repoze.who.plugins)

            config = WhoConfig("/")
            config.parse(
                "[plugin:sibling]\n"
                "use = repoze.who.plugins.sibling_identifier:make_plugin\n"
                "marker = loaded from sibling namespace\n"
                "\n"
                "[identifiers]\n"
                "plugins = sibling\n"
            )

            plugin = config.plugins["sibling"]
            self.assertEqual(plugin.marker, "loaded from sibling namespace")
            self.assertEqual(
                plugin.__class__.__module__,
                "repoze.who.plugins.sibling_identifier",
            )
            self.assertEqual(config.identifiers, [("sibling", plugin)])
        finally:
            sys.path[:] = original_sys_path
            self._clear_repoze_modules()
            sys.modules.update(original_modules)
            shutil.rmtree(str(workspace))
