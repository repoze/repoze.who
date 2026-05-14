import base64
from wsgiref import util as wsgiref_util

from zope.interface.verify import verifyClass

from repoze.who import interfaces
from repoze.who.plugins import basicauth


def _make_wsgi_environ():
    environ = {}
    wsgiref_util.setup_testing_defaults(environ)
    return environ


def test_bap_implements():
    verifyClass(interfaces.IChallenger, basicauth.BasicAuthPlugin)
    verifyClass(interfaces.IIdentifier, basicauth.BasicAuthPlugin)


def test_bap_challenge():
    plugin = basicauth.BasicAuthPlugin("realm")
    environ = _make_wsgi_environ()

    result = plugin.challenge(environ, "401 Unauthorized", [], [])

    assert result is not None

    app_iter = result(environ, lambda *arg: None)

    response = b"".join(app_iter).decode("utf-8")
    assert response.startswith("401 Unauthorized")


def test_bap_identify_noauthinfo():
    plugin = basicauth.BasicAuthPlugin("realm")
    environ = _make_wsgi_environ()
    creds = plugin.identify(environ)
    assert creds is None


def test_bap_identify_nonbasic():
    plugin = basicauth.BasicAuthPlugin("realm")
    environ = _make_wsgi_environ() | {"HTTP_AUTHORIZATION": "Digest abc"}
    creds = plugin.identify(environ)
    assert creds is None


def test_bap_identify_basic_badencoding():
    plugin = basicauth.BasicAuthPlugin("realm")
    environ = _make_wsgi_environ() | {"HTTP_AUTHORIZATION": "Basic abc"}
    creds = plugin.identify(environ)
    assert creds is None


def test_bap_identify_basic_badrepr():
    plugin = basicauth.BasicAuthPlugin("realm")
    value = base64.encodebytes(b"foo").decode("ascii")
    environ = _make_wsgi_environ() | {
        "HTTP_AUTHORIZATION": f"Basic {value}",
    }
    creds = plugin.identify(environ)
    assert creds is None


def test_bap_identify_basic_ok():
    plugin = basicauth.BasicAuthPlugin("realm")
    value = base64.encodebytes(b"foo:bar").decode("ascii")
    environ = _make_wsgi_environ() | {
        "HTTP_AUTHORIZATION": f"Basic {value}",
    }
    creds = plugin.identify(environ)
    assert creds == {"login": "foo", "password": "bar"}


def test_bap_identify_basic_ok_utf8_values():
    LOGIN = b"b\xc3\xa2tard"
    PASSWD = b"l\xc3\xa0 demain"
    plugin = basicauth.BasicAuthPlugin("realm")
    value = base64.encodebytes(b":".join((LOGIN, PASSWD))).decode("ascii")
    environ = _make_wsgi_environ() | {
        "HTTP_AUTHORIZATION": f"Basic {value}",
    }
    creds = plugin.identify(environ)
    assert creds == {
        "login": LOGIN.decode("utf-8"),
        "password": PASSWD.decode("utf-8"),
    }


def test_bap_identify_basic_ok_latin1_values():
    LOGIN = b"b\xe2tard"
    PASSWD = b"l\xe0 demain"
    plugin = basicauth.BasicAuthPlugin("realm")
    value = base64.encodebytes(b":".join((LOGIN, PASSWD))).decode("ascii")
    environ = _make_wsgi_environ() | {
        "HTTP_AUTHORIZATION": f"Basic {value}",
    }
    creds = plugin.identify(environ)
    assert creds == {
        "login": LOGIN.decode("latin1"),
        "password": PASSWD.decode("latin1"),
    }


def test_bap_remember():
    plugin = basicauth.BasicAuthPlugin("realm")
    creds = {}
    environ = _make_wsgi_environ()
    result = plugin.remember(environ, creds)
    assert result is None


def test_bap_forget():
    plugin = basicauth.BasicAuthPlugin("realm")
    creds = {"login": "foo", "password": "password"}
    environ = _make_wsgi_environ()
    result = plugin.forget(environ, creds)
    assert result == [("WWW-Authenticate", 'Basic realm="realm"')]


def test_bap_challenge_forgetheaders_includes():
    plugin = basicauth.BasicAuthPlugin("realm")
    environ = _make_wsgi_environ()
    forget = plugin._get_wwwauth()
    result = plugin.challenge(environ, "401 Unauthorized", [], forget)
    assert forget[0] in result.headers.items()


def test_bap_challenge_forgetheaders_omits():
    plugin = basicauth.BasicAuthPlugin("realm")
    environ = _make_wsgi_environ()
    forget = plugin._get_wwwauth()
    result = plugin.challenge(environ, "401 Unauthorized", [], [])
    assert forget[0] in result.headers.items()


def test_make_plugin():
    plugin = basicauth.make_plugin("realm")
    assert plugin.realm == "realm"
