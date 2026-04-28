import unittest


class ResolveDottedTests(unittest.TestCase):

    def _callFUT(self, dotted_or_ep):
        from repoze.who.utils import resolveDotted
        return resolveDotted(dotted_or_ep)

    def test_resolve_module_colon_object(self):
        resolved = self._callFUT("repoze.who.tests.test_utils:DummyCallable")
        self.assertTrue(resolved is DummyCallable)

    def test_resolve_module_dot_object(self):
        resolved = self._callFUT("repoze.who.tests.test_utils.DummyCallable")
        self.assertTrue(resolved is DummyCallable)

    def test_resolve_module_only(self):
        resolved = self._callFUT("repoze.who.plugins.sql")
        import repoze.who.plugins.sql
        self.assertTrue(resolved is repoze.who.plugins.sql)

    def test_resolve_colon_object_with_extras_suffix(self):
        resolved = self._callFUT(
            "repoze.who.plugins.htpasswd:plain_check [bcrypt]"
        )
        from repoze.who.plugins.htpasswd import plain_check
        self.assertTrue(resolved is plain_check)

    def test_resolve_malformed_colon_form_raises_value_error(self):
        self.assertRaises(
            ValueError,
            self._callFUT,
            "repoze.who.plugins.htpasswd:",
        )

    def test_resolve_module_importerror_not_masked(self):
        import importlib

        original_import_module = importlib.import_module

        def _fake_import_module(name):
            if name == "repoze.who.tests.failing_module":
                raise ModuleNotFoundError(
                    "No module named 'missing_dependency'",
                    name="missing_dependency",
                )
            return original_import_module(name)

        importlib.import_module = _fake_import_module
        try:
            self.assertRaises(
                ModuleNotFoundError,
                self._callFUT,
                "repoze.who.tests.failing_module",
            )
        finally:
            importlib.import_module = original_import_module


class DummyCallable:
    pass
