import hashlib

import pytest
from zope.interface import verify

from repoze.who import interfaces
from repoze.who.plugins import sql


def _make_wsgi_environ():
    environ = {}
    environ["wsgi.version"] = (1, 0)
    return environ


def test_sqlap_implements():
    verify.verifyClass(
        interfaces.IAuthenticator,
        sql.SQLAuthenticatorPlugin,
        tentative=True,
    )


def test_sqlap_authenticate_noresults():
    dummy_factory = DummyConnectionFactory([])
    plugin = sql.SQLAuthenticatorPlugin(
        "select foo from bar", dummy_factory, compare_succeed
    )
    environ = _make_wsgi_environ()
    identity = {"login": "foo", "password": "bar"}
    result = plugin.authenticate(environ, identity)
    assert result is None
    assert dummy_factory.query == "select foo from bar"
    assert dummy_factory.closed


def test_sqlap_authenticate_comparefail():
    dummy_factory = DummyConnectionFactory([["userid", "password"]])
    plugin = sql.SQLAuthenticatorPlugin(
        "select foo from bar", dummy_factory, compare_fail
    )
    environ = _make_wsgi_environ()
    identity = {"login": "fred", "password": "bar"}
    result = plugin.authenticate(environ, identity)
    assert result is None
    assert dummy_factory.query == "select foo from bar"
    assert dummy_factory.closed


def test_sqlap_authenticate_comparesuccess():
    dummy_factory = DummyConnectionFactory([["userid", "password"]])
    plugin = sql.SQLAuthenticatorPlugin(
        "select foo from bar", dummy_factory, compare_succeed
    )
    environ = _make_wsgi_environ()
    identity = {"login": "fred", "password": "bar"}
    result = plugin.authenticate(environ, identity)
    assert result == "userid"
    assert dummy_factory.query == "select foo from bar"
    assert dummy_factory.closed


def test_sqlap_authenticate_nologin():
    dummy_factory = DummyConnectionFactory([["userid", "password"]])
    plugin = sql.SQLAuthenticatorPlugin(
        "select foo from bar", dummy_factory, compare_succeed
    )
    environ = _make_wsgi_environ()
    identity = {}
    result = plugin.authenticate(environ, identity)
    assert result is None
    assert dummy_factory.query is None
    assert not dummy_factory.closed


def _get_sha_hex_digest(clear="password"):
    if not isinstance(clear, bytes):
        clear = clear.encode("utf-8")
    return hashlib.sha1(clear).hexdigest()


def test_sqldpc_shaprefix_success():
    stored = "{SHA}" + _get_sha_hex_digest()
    result = sql.default_password_compare("password", stored)
    assert result


def test_sqldpc_shaprefix_w_unicode_cleartext():
    stored = "{SHA}" + _get_sha_hex_digest()
    result = sql.default_password_compare("password", stored)
    assert result


def test_sqldpc_shaprefix_fail():
    stored = "{SHA}" + _get_sha_hex_digest()
    result = sql.default_password_compare("notpassword", stored)
    assert not result


def test_sqldpc_noprefix_success():
    stored = "password"
    result = sql.default_password_compare("password", stored)
    assert result


def test_sqldpc_noprefix_fail():
    stored = "password"
    result = sql.default_password_compare("notpassword", stored)
    assert not result


def test_sqlmdp_implements():
    verify.verifyClass(
        interfaces.IMetadataProvider,
        sql.SQLMetadataProviderPlugin,
        tentative=True,
    )


def test_sqlmdp_add_metadata():
    dummy_factory = DummyConnectionFactory([[1, 2, 3]])

    def dummy_filter(results):
        return results

    plugin = sql.SQLMetadataProviderPlugin(
        "md",
        "select foo from bar",
        dummy_factory,
        dummy_filter,
    )
    environ = {}
    identity = {"repoze.who.userid": 1}
    plugin.add_metadata(environ, identity)
    assert dummy_factory.closed
    assert identity["md"] == [[1, 2, 3]]
    assert dummy_factory.query == "select foo from bar"
    assert "__userid" not in identity


def test_map_noquery():
    with pytest.raises(sql.QueryRequired):
        sql.make_authenticator_plugin(None, "conn", "compare")


def test_map_no_connfactory():
    with pytest.raises(sql.ConnFactoryRequired):
        sql.make_authenticator_plugin("statement", None, "compare")


def test_map_bad_connfactory():
    with pytest.raises(sql.InvalidConnFactory):
        sql.make_authenticator_plugin("statement", "does.not:exist", None)


def test_map_connfactory_specd():
    plugin = sql.make_authenticator_plugin(
        "statement",
        "plugins.test_sql:make_dummy_connfactory",
        None,
    )
    assert plugin.query == "statement"
    assert plugin.conn_factory is DummyConnFactory
    assert plugin.compare_fn is sql.default_password_compare


def test_map_comparefunc_specd():
    plugin = sql.make_authenticator_plugin(
        "statement",
        "plugins.test_sql:make_dummy_connfactory",
        "plugins.test_sql:make_dummy_connfactory",
    )
    assert plugin.query == "statement"
    assert plugin.conn_factory is DummyConnFactory
    assert plugin.compare_fn == make_dummy_connfactory


def test_msmdp_no_query():
    with pytest.raises(sql.QueryRequired):
        sql.make_metadata_plugin(
            "name",
            None,
            None,
        )


def test_msmdp_no_connfactory():
    with pytest.raises(sql.ConnFactoryRequired):
        sql.make_metadata_plugin(
            "name",
            "statement",
            None,
        )


def test_msmdp_bad_connfactory():
    with pytest.raises(sql.InvalidConnFactory):
        sql.make_metadata_plugin(
            "name",
            "statement",
            "does.not:exist",
            None,
        )


def test_msmdp_connfactory_specd():
    plugin = sql.make_metadata_plugin(
        "name",
        "statement",
        "plugins.test_sql:make_dummy_connfactory",
        None,
    )
    assert plugin.name == "name"
    assert plugin.query == "statement"
    assert plugin.conn_factory is DummyConnFactory
    assert plugin.filter is None


def test_msmdp_comparefn_specified():
    plugin = sql.make_metadata_plugin(
        "name",
        "statement",
        "plugins.test_sql:make_dummy_connfactory",
        "plugins.test_sql:make_dummy_connfactory",
    )
    assert plugin.name == "name"
    assert plugin.query == "statement"
    assert plugin.conn_factory is DummyConnFactory
    assert plugin.filter is make_dummy_connfactory


class DummyConnectionFactory:
    # acts as all of: a factory, a connection, and a cursor
    closed = False
    query = None

    def __init__(self, results):
        self.results = results

    def __call__(self):
        return self

    def cursor(self):
        return self

    def execute(self, query, *arg):
        self.query = query
        self.bindargs = arg

    def fetchall(self):
        return self.results

    def fetchone(self):
        if self.results:
            return self.results[0]
        return []

    def close(self):
        self.closed = True


def compare_fail(cleartext, stored):
    return False


def compare_succeed(cleartext, stored):
    return True


class _DummyConnFactory:
    pass


DummyConnFactory = _DummyConnFactory()


def make_dummy_connfactory(**kw):
    return DummyConnFactory
