import hashlib
import struct
from unittest import mock

import pytest

from repoze.who import _auth_tkt
from repoze.who import _helpers

SECRET = "SEEKRIT"
IP = "1.2.3.4"
USERID = "USERID"
_WHEN = 1234567


def test_authticket_ctor_w_userid_w_embedded_bang():
    with pytest.raises(_auth_tkt.InvalidFieldSeparator) as exc_info:
        _auth_tkt.AuthTicket(SECRET, "USER!ID", IP)

    assert exc_info.value.fieldname == "'userid'"
    assert exc_info.value.separator == "!"


def test_authticket_ctor_w_token_w_embedded_bang():
    tokens = ("a!b",)  # cannot be safely round-tripped

    with pytest.raises(_auth_tkt.InvalidFieldSeparator) as exc_info:
        _auth_tkt.AuthTicket(SECRET, USERID, IP, tokens=tokens)

    assert exc_info.value.fieldname == "'token' values"
    assert exc_info.value.separator == "!"


def test_authticket_ctor_w_token_w_embedded_comma():
    tokens = ("a,b",)  # cannot be safely round-tripped

    with pytest.raises(_auth_tkt.InvalidFieldSeparator) as exc_info:
        _auth_tkt.AuthTicket(SECRET, USERID, IP, tokens=tokens)

    assert exc_info.value.fieldname == "'token' values"
    assert exc_info.value.separator == ","


def test_authticket_ctor_w_user_data_w_embedded_bang():
    user_data = "DATA!HERE"  # cannot be safely round-tripped

    with pytest.raises(_auth_tkt.InvalidFieldSeparator) as exc_info:
        _auth_tkt.AuthTicket(SECRET, USERID, IP, user_data=user_data)

    assert exc_info.value.fieldname == "'user_data'"
    assert exc_info.value.separator == "!"


def test_authticket_ctor_defaults():
    with mock.patch("time.time", return_value=_WHEN):
        tkt = _auth_tkt.AuthTicket(SECRET, USERID, IP)

    assert tkt.secret == SECRET
    assert tkt.userid == USERID
    assert tkt.ip == IP
    assert tkt.tokens == ""
    assert tkt.user_data == ""
    assert tkt.time == _WHEN
    assert tkt.cookie_name == "auth_tkt"
    assert not tkt.secure
    assert tkt.digest_algo is hashlib.md5


def test_authticket_ctor_explicit():
    tkt = _auth_tkt.AuthTicket(
        SECRET,
        USERID,
        IP,
        tokens=("a", "b"),
        user_data="DATA",
        time=_WHEN,
        cookie_name="oatmeal",
        secure=True,
        digest_algo=hashlib.sha512,
    )

    assert tkt.secret == SECRET
    assert tkt.userid == USERID
    assert tkt.ip == IP
    assert tkt.tokens == "a,b"
    assert tkt.user_data == "DATA"
    assert tkt.time == _WHEN
    assert tkt.cookie_name == "oatmeal"
    assert tkt.secure
    assert tkt.digest_algo is hashlib.sha512


def test_authticket_ctor_w_string_algorithm():
    tkt = _auth_tkt.AuthTicket(
        SECRET,
        USERID,
        IP,
        tokens=("a", "b"),
        user_data="DATA",
        time=_WHEN,
        cookie_name="oatmeal",
        secure=True,
        digest_algo="sha1",
    )

    assert tkt.secret == SECRET
    assert tkt.userid == USERID
    assert tkt.ip == IP
    assert tkt.tokens == "a,b"
    assert tkt.user_data == "DATA"
    assert tkt.time == _WHEN
    assert tkt.cookie_name == "oatmeal"
    assert tkt.secure
    assert tkt.digest_algo is hashlib.sha1


def test_authtkt_digest():
    expected = _auth_tkt.calculate_digest(
        IP,
        _WHEN,
        SECRET,
        USERID,
        "a,b",
        "DATA",
        hashlib.md5,
    )
    tkt = _auth_tkt.AuthTicket(
        SECRET,
        USERID,
        IP,
        tokens=("a", "b"),
        user_data="DATA",
        time=_WHEN,
        cookie_name="oatmeal",
        secure=True,
    )

    result = tkt.digest()

    assert result == expected


def test_authtkt_cookie_value_wo_tokens_or_userdata():
    digest = _auth_tkt.calculate_digest(
        IP, _WHEN, SECRET, USERID, "", "", hashlib.md5
    )
    expected = f"{digest}{_WHEN:08x}USERID!"
    tkt = _auth_tkt.AuthTicket(SECRET, USERID, IP, time=_WHEN)

    result = tkt.cookie_value()

    assert result == expected


def test_authtkt_cookie_value_w_tokens_and_userdata():
    digest = _auth_tkt.calculate_digest(
        IP,
        _WHEN,
        SECRET,
        USERID,
        "a,b",
        "DATA",
        hashlib.md5,
    )
    expected = f"{digest}{_WHEN:08x}USERID!a,b!DATA"
    tkt = _auth_tkt.AuthTicket(
        SECRET,
        USERID,
        IP,
        tokens=("a", "b"),
        user_data="DATA",
        time=_WHEN,
    )

    result = tkt.cookie_value()

    assert result == expected


def _encode_digest(digest, suffix):
    to_encode = f"{digest}{_WHEN:08x}{suffix}"
    return _helpers.encodestring(to_encode).strip()


def test_authtkt_cookie_value_wo_secure_wo_tokens_or_userdata():
    digest = _auth_tkt.calculate_digest(
        IP,
        _WHEN,
        SECRET,
        USERID,
        "",
        "",
        hashlib.md5,
    )
    expected = _encode_digest(digest, "USERID!")
    tkt = _auth_tkt.AuthTicket(
        SECRET, USERID, IP, time=_WHEN, cookie_name="oatmeal"
    )

    cookie = tkt.cookie()

    assert cookie["oatmeal"].value == expected
    assert cookie["oatmeal"]["path"] == "/"
    assert cookie["oatmeal"]["secure"] == ""


def test_authtkt_cookie_value_w_secure_w_tokens_and_userdata():
    digest = _auth_tkt.calculate_digest(
        IP,
        _WHEN,
        SECRET,
        USERID,
        "a,b",
        "DATA",
        hashlib.md5,
    )
    expected = _encode_digest(digest, "USERID!a,b!DATA")
    tkt = _auth_tkt.AuthTicket(
        SECRET,
        USERID,
        IP,
        tokens=("a", "b"),
        user_data="DATA",
        time=_WHEN,
        cookie_name="oatmeal",
        secure=True,
    )

    cookie = tkt.cookie()

    assert cookie["oatmeal"].value == expected
    assert cookie["oatmeal"]["path"] == "/"
    assert cookie["oatmeal"]["secure"] == "true"


def test_bad_ticket_wo_expected():
    exc = _auth_tkt.BadTicket("message")

    assert exc.args == ("message",)
    assert exc.expected is None


def test_bad_ticket_w_expected():
    exc = _auth_tkt.BadTicket("message", "foo")

    assert exc.args == ("message",)
    assert exc.expected == "foo"


def test_parse_ticket_w_bad_timestamp():
    ticket = "12345678901234567890123456789012XXXXXXXXuserid!"

    with pytest.raises(_auth_tkt.BadTicket) as exc_info:
        _auth_tkt.parse_ticket(SECRET, ticket, IP, "md5")

    assert exc_info.value.args[0].startswith("Timestamp is not a hex integer:")


def test_parse_ticket_w_no_bang_after_userid():
    ticket = "1234567890123456789012345678901201020304userid"

    with pytest.raises(_auth_tkt.BadTicket) as exc_info:
        _auth_tkt.parse_ticket(SECRET, ticket, IP, "md5")

    assert exc_info.value.args[0] == "userid is not followed by !"


def test_parse_ticket_w_wo_tokens_or_data_bad_digest():
    ticket = "1234567890123456789012345678901201020304userid!"

    with pytest.raises(_auth_tkt.BadTicket) as exc_info:
        _auth_tkt.parse_ticket(SECRET, ticket, IP, "md5")

    assert exc_info.value.args[0] == "Digest signature is not correct"


def test_parse_ticket_w_wo_tokens_or_data_ok_digest():
    digest = _auth_tkt.calculate_digest(
        IP, _WHEN, SECRET, USERID, "", "", hashlib.md5
    )
    ticket = f"{digest}{_WHEN:08x}USERID!"

    timestamp, userid, tokens, user_data = _auth_tkt.parse_ticket(
        SECRET,
        ticket,
        IP,
        "md5",
    )

    assert timestamp == _WHEN
    assert userid == USERID
    assert tokens == [""]
    assert user_data == ""


def test_parse_ticket_w_w_tokens_and_data_ok_digest():
    digest = _auth_tkt.calculate_digest(
        IP,
        _WHEN,
        SECRET,
        USERID,
        "a,b",
        "DATA",
        hashlib.md5,
    )
    ticket = f"{digest}{_WHEN:08x}USERID!a,b!DATA"

    timestamp, userid, tokens, user_data = _auth_tkt.parse_ticket(
        SECRET,
        ticket,
        IP,
        "md5",
    )

    assert timestamp == _WHEN
    assert userid == USERID
    assert tokens == ["a", "b"]
    assert user_data == "DATA"


def test_parse_ticket_w_w_tokens_and_data_ok_alternate_digest():
    digest = _auth_tkt.calculate_digest(
        IP,
        _WHEN,
        SECRET,
        USERID,
        "a,b",
        "DATA",
        hashlib.sha256,
    )
    ticket = f"{digest}{_WHEN:08x}USERID!a,b!DATA"

    timestamp, userid, tokens, user_data = _auth_tkt.parse_ticket(
        SECRET,
        ticket,
        IP,
        hashlib.sha256,
    )

    assert timestamp == _WHEN
    assert userid == USERID
    assert tokens == ["a", "b"]
    assert user_data == "DATA"


# calculate_digest is not very testable, fully exercised through callers.


def test_encode_ip_timestamp():
    result = _auth_tkt.encode_ip_timestamp("1.2.3.4", _WHEN)

    assert result == struct.pack(">BBBBL", 1, 2, 3, 4, _WHEN)


def test_maybe_encode_bytes_w_bytes():
    foo = b"foo"

    result = _auth_tkt.maybe_encode(foo)

    assert result is foo


def test_maybe_encode_w_str():
    foo = "foo"

    result = _auth_tkt.maybe_encode(foo)

    assert result == b"foo"
