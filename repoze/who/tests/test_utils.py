import unittest


class ResolveDottedTests(unittest.TestCase):

    def _callFUT(self, dotted_or_ep):
        from repoze.who.utils import resolveDotted
        return resolveDotted(dotted_or_ep)

    def test_resolve_module_colon_object(self):
        resolved = self._callFUT("repoze.who.tests.test_utils:DummyCallable")
        self.assertEqual(resolved.__name__, "DummyCallable")
        self.assertIn("test_utils", resolved.__module__)

    def test_resolve_missing_colon_raises_value_error(self):
        self.assertRaises(
            ValueError,
            self._callFUT,
            "repoze.who.tests.test_utils.DummyCallable",
        )

    def test_resolve_empty_object_raises_value_error(self):
        self.assertRaises(
            ValueError,
            self._callFUT,
            "repoze.who.tests.test_utils:",
        )

    def test_resolve_extras_suffix_raises_value_error(self):
        self.assertRaises(
            ValueError,
            self._callFUT,
            "repoze.who.tests.test_utils:DummyCallable [extra]",
        )


class DummyCallable:
    pass
