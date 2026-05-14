import datetime
import hashlib
import time
from unittest import mock
from wsgiref import util as wsgiref_util

import pytest
from zope.interface import verify

from repoze.who import _auth_tkt
from repoze.who import interfaces
from repoze.who.plugins import auth_tkt

REMOTE_ADDR = "1.1.1.1"
HTTP_HOST = "localhost"
SECRET = "s33kr3t"
USERID = "userid"


def _make_wsgi_environ():
    environ = {}
    wsgiref_util.setup_testing_defaults(environ)
    environ["REMOTE_ADDR"] = REMOTE_ADDR
    environ["HTTP_HOST"] = HTTP_HOST
    return environ


def _makeTicket(
    userid=USERID,
    remote_addr="0.0.0.0",
    tokens=(),
    userdata="userdata",
    cookie_name="auth_tkt",
    secure=False,
    time=None,
    digest_algo="md5",
):
    ticket = _auth_tkt.AuthTicket(
        SECRET,
        userid,
        remote_addr,
        tokens=list(tokens),
        user_data=userdata,
        time=time,
        cookie_name=cookie_name,
        secure=secure,
        digest_algo=digest_algo,
    )

    return ticket.cookie_value()


def _check_tkt_cookies(result, tkt, suffix=""):
    assert len(result) == 3
    assert result[0] == ("Set-Cookie", f'auth_tkt="{tkt}"; Path=/{suffix}')
    assert result[1] == (
        "Set-Cookie",
        f'auth_tkt="{tkt}"; Path=/; Domain=localhost{suffix}',
    )
    assert result[2] == (
        "Set-Cookie",
        f'auth_tkt="{tkt}"; Path=/; Domain=.localhost{suffix}',
    )


def test_atcp_class_conforms_to_IIdentifier():
    verify.verifyClass(
        interfaces.IIdentifier,
        auth_tkt.AuthTktCookiePlugin,
    )


def test_atcp_instance_conforms_to_IIdentifier():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    verify.verifyObject(interfaces.IIdentifier, plugin)


def test_atcp_class_conforms_to_IAuthenticator():
    verify.verifyClass(
        interfaces.IAuthenticator,
        auth_tkt.AuthTktCookiePlugin,
    )


def test_atcp_instance_conforms_to_IAuthenticator():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    verify.verifyObject(interfaces.IAuthenticator, plugin)


def test_atcp_ctor_timeout_no_reissue():
    with pytest.raises(auth_tkt.ReissueTimeMustBeLowerThanTimeout):
        auth_tkt.AuthTktCookiePlugin(SECRET, "userid", timeout=1)


def test_atcp_ctor_timeout_lower_than_reissue():
    with pytest.raises(auth_tkt.ReissueTimeMustBeLowerThanTimeout):
        auth_tkt.AuthTktCookiePlugin(
            SECRET,
            "userid",
            timeout=1,
            reissue_time=2,
        )


def test_atcp_identify_nocookie():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    environ = _make_wsgi_environ()

    result = plugin.identify(environ)

    assert result is None


def test_atcp_identify_good_cookie_include_ip():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        include_ip=True,
    )
    val = _makeTicket(
        remote_addr="1.1.1.1",
        userdata="foo=123",
    )
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={val}"}

    result = plugin.identify(environ)

    assert len(result) == 4
    assert result["tokens"] == [""]
    assert result["repoze.who.plugins.auth_tkt.userid"] == "userid"
    assert result["userdata"] == {"foo": "123"}
    assert "timestamp" in result
    assert environ["REMOTE_USER_TOKENS"] == [""]
    assert environ["REMOTE_USER_DATA"] == "foo=123"
    assert environ["AUTH_TYPE"] == "cookie"


def test_atcp_identify_good_cookie_dont_include_ip():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        include_ip=False,
    )
    val = _makeTicket(userdata="foo=123")
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={val}"}

    result = plugin.identify(environ)

    assert len(result) == 4
    assert result["tokens"] == [""]
    assert result["repoze.who.plugins.auth_tkt.userid"] == "userid"
    assert result["userdata"] == {"foo": "123"}
    assert "timestamp" in result
    assert environ["REMOTE_USER_TOKENS"] == [""]
    assert environ["REMOTE_USER_DATA"] == "foo=123"
    assert environ["AUTH_TYPE"] == "cookie"


def test_atcp_identify_good_cookie_int_useridtype():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        include_ip=False,
    )
    val = _makeTicket(
        userid="1",
        userdata="userid_type=int",
    )
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={val}"}

    result = plugin.identify(environ)

    assert len(result) == 4
    assert result["tokens"] == [""]
    assert result["repoze.who.plugins.auth_tkt.userid"] == 1
    assert result["userdata"] == {"userid_type": "int"}
    assert "timestamp" in result
    assert environ["REMOTE_USER_TOKENS"] == [""]
    assert environ["REMOTE_USER_DATA"] == "userid_type=int"
    assert environ["AUTH_TYPE"] == "cookie"


def test_atcp_identify_good_cookie_unknown_useridtype():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        include_ip=False,
    )
    val = _makeTicket(
        userid="userid",
        userdata="userid_type=unknown",
    )
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={val}"}

    result = plugin.identify(environ)

    assert len(result) == 4
    assert result["tokens"] == [""]
    assert result["repoze.who.plugins.auth_tkt.userid"] == "userid"
    assert result["userdata"] == {"userid_type": "unknown"}
    assert "timestamp" in result
    assert environ["REMOTE_USER_TOKENS"] == [""]
    assert environ["REMOTE_USER_DATA"] == "userid_type=unknown"
    assert environ["AUTH_TYPE"] == "cookie"


def test_atcp_identify_bad_cookie():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        include_ip=True,
    )
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": "auth_tkt=bogus"}

    result = plugin.identify(environ)

    assert result is None


def test_atcp_identify_bad_cookie_expired():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        timeout=2,
        reissue_time=1,
    )
    val = _makeTicket(
        userid="userid",
        time=time.time() - 3,
    )
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={val}"}

    result = plugin.identify(environ)

    assert result is None


def test_atcp_identify_with_checker_and_existing_account():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        userid_checker=dummy_userid_checker,
    )
    val = _makeTicket(
        userid="existing",
        userdata="foo=123",
    )
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={val}"}

    result = plugin.identify(environ)

    assert len(result) == 4
    assert result["tokens"] == [""]
    assert result["repoze.who.plugins.auth_tkt.userid"] == "existing"
    assert result["userdata"] == {"foo": "123"}
    assert "timestamp" in result
    assert environ["REMOTE_USER_TOKENS"] == [""]
    assert environ["REMOTE_USER_DATA"] == "foo=123"
    assert environ["AUTH_TYPE"] == "cookie"


def test_atcp_identify_with_alternate_hash():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        include_ip=False,
        digest_algo="sha256",
    )
    val = _makeTicket(
        userdata="foo=123",
        digest_algo="sha256",
    )
    md5_val = _makeTicket(userdata="foo=123")

    assert val != md5_val
    # md5 is 16*2 characters long, sha256 is 32*2

    assert len(val) == len(md5_val) + 32
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={val}"}

    result = plugin.identify(environ)

    assert len(result) == 4
    assert result["tokens"] == [""]
    assert result["repoze.who.plugins.auth_tkt.userid"] == "userid"
    assert result["userdata"] == {"foo": "123"}
    assert "timestamp" in result
    assert environ["REMOTE_USER_TOKENS"] == [""]
    assert environ["REMOTE_USER_DATA"] == "foo=123"
    assert environ["AUTH_TYPE"] == "cookie"


def test_atcp_identify_bad_cookie_with_alternate_hash():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        include_ip=True,
        digest_algo="sha256",
    )
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": "auth_tkt=bogus"}

    result = plugin.identify(environ)

    assert result is None


def test_atcp_remember_creds_same():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    val = _makeTicket(userid="userid", userdata="foo=123")
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={val}"}

    result = plugin.remember(
        environ, {"repoze.who.userid": "userid", "userdata": {"foo": "123"}}
    )

    assert result is None


def test_atcp_remember_creds_same_alternate_hash():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET, digest_algo="sha1")
    val = _makeTicket(userid="userid", userdata="foo=123", digest_algo="sha1")
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={val}"}

    result = plugin.remember(
        environ, {"repoze.who.userid": "userid", "userdata": {"foo": "123"}}
    )

    assert result is None


def test_atcp_remember_creds_hash_mismatch():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET, digest_algo="sha1")
    old_val = _makeTicket(
        userid="userid",
        userdata="foo=123",
        digest_algo="md5",
    )
    new_val = _makeTicket(
        userid="userid",
        userdata="foo=123",
        digest_algo="sha1",
    )
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={old_val}"}

    result = plugin.remember(
        environ,
        {
            "repoze.who.userid": "userid",
            "userdata": {"foo": "123"},
        },
    )

    _check_tkt_cookies(result, new_val)


def test_atcp_remember_creds_secure_alternate_hash():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        secure=True,
        digest_algo="sha512",
    )
    val = _makeTicket(
        userid="userid",
        secure=True,
        userdata="foo=123",
        digest_algo="sha512",
    )
    environ = _make_wsgi_environ()

    result = plugin.remember(
        environ, {"repoze.who.userid": "userid", "userdata": {"foo": "123"}}
    )

    _check_tkt_cookies(result, val, suffix="; secure; HttpOnly")


def test_atcp_remember_creds_secure():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET, secure=True)
    val = _makeTicket(
        userid="userid",
        secure=True,
        userdata="foo=123",
    )
    environ = _make_wsgi_environ()

    result = plugin.remember(
        environ, {"repoze.who.userid": "userid", "userdata": {"foo": "123"}}
    )

    _check_tkt_cookies(result, val, suffix="; secure; HttpOnly")


def test_atcp_remember_creds_samesite():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        secure=False,
        samesite="Strict",
    )
    val = _makeTicket(
        userid="userid",
        secure=False,
        userdata="foo=123",
    )
    environ = _make_wsgi_environ()

    result = plugin.remember(
        environ, {"repoze.who.userid": "userid", "userdata": {"foo": "123"}}
    )

    _check_tkt_cookies(result, val, suffix="; SameSite=Strict")


def test_atcp_remember_creds_different():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    old_val = _makeTicket(userid="userid")
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={old_val}"}
    new_val = _makeTicket(userid="other", userdata="foo=123")

    result = plugin.remember(
        environ, {"repoze.who.userid": "other", "userdata": {"foo": "123"}}
    )

    _check_tkt_cookies(result, new_val)


def test_atcp_remember_creds_different_strips_port():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    old_val = _makeTicket(userid="userid")
    environ = _make_wsgi_environ() | {
        "HTTP_COOKIE": f"auth_tkt={old_val}",
        "HTTP_HOST": "localhost:8080",
    }
    new_val = _makeTicket(userid="other", userdata="foo=123")

    result = plugin.remember(
        environ, {"repoze.who.userid": "other", "userdata": {"foo": "123"}}
    )

    _check_tkt_cookies(result, new_val)


def test_atcp_remember_creds_different_include_ip():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET, include_ip=True)
    old_val = _makeTicket(
        userid="userid",
        remote_addr="1.1.1.1",
    )
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={old_val}"}
    new_val = _makeTicket(
        userid="other",
        userdata="foo=123",
        remote_addr="1.1.1.1",
    )

    result = plugin.remember(
        environ,
        {
            "repoze.who.userid": "other",
            "userdata": {"foo": "123"},
        },
    )

    _check_tkt_cookies(result, new_val)


def test_atcp_remember_creds_different_bad_old_cookie():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    old_val = "BOGUS"
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={old_val}"}
    new_val = _makeTicket(
        userid="other",
        userdata="foo=123",
    )

    result = plugin.remember(
        environ,
        {
            "repoze.who.userid": "other",
            "userdata": {"foo": "123"},
        },
    )

    _check_tkt_cookies(result, new_val)


def test_atcp_remember_creds_different_with_tokens():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    old_val = _makeTicket(userid="userid")
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={old_val}"}
    new_val = _makeTicket(
        userid="userid",
        userdata="foo=123",
        tokens=["foo", "bar"],
    )

    result = plugin.remember(
        environ,
        {
            "repoze.who.userid": "userid",
            "userdata": {"foo": "123"},
            "tokens": ["foo", "bar"],
        },
    )

    _check_tkt_cookies(result, new_val)


def test_atcp_remember_creds_different_with_tuple_tokens():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    old_val = _makeTicket(userid="userid")
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={old_val}"}
    new_val = _makeTicket(
        userid="userid",
        userdata="foo=123",
        tokens=["foo", "bar"],
    )

    result = plugin.remember(
        environ,
        {
            "repoze.who.userid": "userid",
            "userdata": {"foo": "123"},
            "tokens": ("foo", "bar"),
        },
    )

    _check_tkt_cookies(result, new_val)


def test_atcp_remember_creds_different_int_userid():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    old_val = _makeTicket(userid="userid")
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={old_val}"}
    new_val = _makeTicket(
        userid="1",
        userdata="userid_type=int",
    )

    result = plugin.remember(
        environ,
        {
            "repoze.who.userid": 1,
            "userdata": {},
        },
    )

    _check_tkt_cookies(result, new_val)


def test_atcp_remember_creds_different_unicode_userid():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    old_val = _makeTicket(userid="userid")
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={old_val}"}
    userid = b"\xc2\xa9".decode("utf-8")
    userdata = ""
    new_val = _makeTicket(
        userid=userid.encode("utf-8"),
        userdata=userdata,
    )

    result = plugin.remember(
        environ,
        {
            "repoze.who.userid": userid,
            "userdata": {},
        },
    )

    _check_tkt_cookies(result, new_val)


def test_atcp_remember_creds_reissue():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET, reissue_time=1)
    old_val = _makeTicket(userid="userid", userdata="", time=time.time() - 2)
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={old_val}"}
    new_val = _makeTicket(
        userid="userid",
        userdata="",
    )

    result = plugin.remember(
        environ,
        {
            "repoze.who.userid": "userid",
            "userdata": "",
        },
    )

    _check_tkt_cookies(result, new_val)


def test_atcp_remember_creds_reissue_alternate_hash():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        reissue_time=1,
        digest_algo="sha256",
    )
    old_val = _makeTicket(
        userid="userid",
        userdata="",
        time=time.time() - 2,
        digest_algo="sha256",
    )
    environ = _make_wsgi_environ() | {"HTTP_COOKIE": f"auth_tkt={old_val}"}
    new_val = _makeTicket(
        userid="userid",
        userdata="",
        digest_algo="sha256",
    )

    result = plugin.remember(
        environ,
        {
            "repoze.who.userid": "userid",
            "userdata": "",
        },
    )

    _check_tkt_cookies(result, new_val)


def test_atcp_remember_l10n_sane_cookie_date():
    now = datetime.datetime(2009, 11, 8, 16, 15, 22)
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    environ = {"HTTP_HOST": "example.com"}
    tkt = _makeTicket(userid="chris", userdata="")

    with mock.patch("repoze.who.plugins.auth_tkt._UTCNOW", now):
        result = plugin.remember(
            environ,
            {
                "repoze.who.userid": "chris",
                "max_age": "500",
            },
        )

    name, value = result.pop(0)

    assert name == "Set-Cookie"
    assert value.startswith(f'auth_tkt="{tkt}"; Path=/; Max-Age=500')
    assert value.endswith("; Expires=Sun, 08 Nov 2009 16:23:42 GMT")


def test_atcp_remember_max_age():
    now = datetime.datetime(2009, 11, 8, 16, 15, 22)

    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    environ = {"HTTP_HOST": "example.com"}
    tkt = _makeTicket(
        userid="chris",
        userdata="",
    )

    with mock.patch("repoze.who.plugins.auth_tkt._UTCNOW", now):
        result = plugin.remember(
            environ,
            {
                "repoze.who.userid": "chris",
                "max_age": "500",
            },
        )

    name, value = result.pop(0)
    assert name == "Set-Cookie"
    assert value.startswith(f'auth_tkt="{tkt}"; Path=/; Max-Age=500')
    assert value.endswith("; Expires=Sun, 08 Nov 2009 16:23:42 GMT")

    name, value = result.pop(0)
    assert name == "Set-Cookie"
    assert value.startswith(
        f'auth_tkt="{tkt}"; Path=/; Domain=example.com; Max-Age=500'
    )
    assert value.endswith("; Expires=Sun, 08 Nov 2009 16:23:42 GMT")

    name, value = result.pop(0)
    assert name == "Set-Cookie"
    assert value.startswith(
        f'auth_tkt="{tkt}"; Path=/; Domain=.example.com; Max-Age=500'
    )
    assert value.endswith("; Expires=Sun, 08 Nov 2009 16:23:42 GMT")


def test_atcp_remember_max_age_unicode():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    environ = {"HTTP_HOST": "example.com"}
    tkt = _makeTicket(
        userid="chris",
        userdata="",
    )

    result = plugin.remember(
        environ,
        {
            "repoze.who.userid": "chris",
            "max_age": "500",
        },
    )

    name, value = result.pop(0)
    assert name == "Set-Cookie"
    assert isinstance(value, str)
    assert value.startswith(f'auth_tkt="{tkt}"; Path=/; Max-Age=500')
    assert "; Expires=" in value

    name, value = result.pop(0)
    assert name == "Set-Cookie"
    assert value.startswith(
        f'auth_tkt="{tkt}"; Path=/; Domain=example.com; Max-Age=500'
    )
    assert "; Expires=" in value

    name, value = result.pop(0)
    assert name == "Set-Cookie"
    assert value.startswith(
        f'auth_tkt="{tkt}"; Path=/; Domain=.example.com; Max-Age=500'
    )
    assert "; Expires=" in value


def test_atcp_forget():
    now = datetime.datetime(2009, 11, 5, 16, 15, 22)
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    environ = _make_wsgi_environ()

    with mock.patch("repoze.who.plugins.auth_tkt._UTCNOW", now):
        headers = plugin.forget(environ, None)

    _check_tkt_cookies(
        headers,
        "INVALID",
        "; Max-Age=0; Expires=Thu, 05 Nov 2009 16:15:22 GMT",
    )


def test_atcp_authenticate_non_auth_tkt_credentials():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)

    result = plugin.authenticate(environ={}, identity={})

    assert result is None


def test_atcp_authenticate_without_checker():
    plugin = auth_tkt.AuthTktCookiePlugin(SECRET)
    identity = {"repoze.who.plugins.auth_tkt.userid": "phred"}

    result = plugin.authenticate({}, identity)

    assert result == "phred"


def test_atcp_authenticate_with_checker_and_non_existing_account():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        userid_checker=dummy_userid_checker,
    )
    identity = {"repoze.who.plugins.auth_tkt.userid": "phred"}

    result = plugin.authenticate({}, identity)

    assert result is None


def test_atcp_authenticate_with_checker_and_existing_account():
    plugin = auth_tkt.AuthTktCookiePlugin(
        SECRET,
        userid_checker=dummy_userid_checker,
    )
    identity = {"repoze.who.plugins.auth_tkt.userid": "existing"}

    result = plugin.authenticate({}, identity)
    assert result == "existing"


@pytest.fixture
def secret_file(tmp_path):
    return tmp_path / "secret.txt"


def test_make_plugin_wo_secret_wo_secretfile():
    with pytest.raises(auth_tkt.ExactlyOneOfSecretOrSecretFile):
        auth_tkt.make_plugin()


def test_make_plugin_w_secret_w_secretfile():
    with pytest.raises(auth_tkt.ExactlyOneOfSecretOrSecretFile):
        auth_tkt.make_plugin(SECRET, "secretfile")


def test_make_plugin_w_bad_secretfile(secret_file):
    with pytest.raises(auth_tkt.InvalidSecretfile):
        auth_tkt.make_plugin(secretfile=str(secret_file))


def test_make_plugin_w_secret():
    plugin = auth_tkt.make_plugin(SECRET)
    assert plugin.cookie_name == "auth_tkt"
    assert plugin.secret == SECRET
    assert not plugin.include_ip
    assert not plugin.secure


def test_make_plugin_w_secretfile(secret_file):
    secret_file.write_text("s33kr1t\n")
    plugin = auth_tkt.make_plugin(secretfile=str(secret_file))
    assert plugin.secret == "s33kr1t"


def test_make_plugin_with_timeout_and_reissue_time():
    plugin = auth_tkt.make_plugin(SECRET, timeout=5, reissue_time=1)
    assert plugin.timeout == 5
    assert plugin.reissue_time == 1


def test_make_plugin_with_userid_checker():
    plugin = auth_tkt.make_plugin(
        SECRET,
        userid_checker="repoze.who.plugins.auth_tkt:make_plugin",
    )

    assert plugin.userid_checker is auth_tkt.make_plugin


def test_make_plugin_with_alternate_hash():
    plugin = auth_tkt.make_plugin(SECRET, digest_algo="sha1")

    assert plugin.digest_algo is hashlib.sha1


def test_make_plugin_with_alternate_hash_func():
    plugin = auth_tkt.make_plugin(SECRET, digest_algo=hashlib.sha1)

    assert plugin.digest_algo is hashlib.sha1


def test_make_plugin_with_bogus_hash():
    with pytest.raises(auth_tkt.InvalidDigestAlgo):
        auth_tkt.make_plugin(secret="fiddly", digest_algo="foo23")


def dummy_userid_checker(userid):
    return userid == "existing"
