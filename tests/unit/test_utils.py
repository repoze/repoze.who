import pytest

from repoze.who import utils


def test_resolve_dotted_w_module_colon_object():
    resolved = utils.resolveDotted("test_utils:DummyCallable")
    assert resolved.__name__ == "DummyCallable"
    assert "test_utils" in resolved.__module__


def test_resolve_dotted_w_missing_colon():
    with pytest.raises(utils.InvalidDottedName):
        utils.resolveDotted("test_utils.DummyCallable")


def test_resolve_dotted_w_empty_object():
    with pytest.raises(utils.InvalidDottedName):
        utils.resolveDotted("test_utils:")


def test_resolve_dotted_w_extras_suffix():
    with pytest.raises(utils.InvalidDottedName):
        utils.resolveDotted("test_utils:DummyCallable [extra]")


class DummyCallable:
    pass
