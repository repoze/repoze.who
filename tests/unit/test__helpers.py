from http import cookies as http_cookies # SimpleCookie

import pytest

from repoze.who import _helpers # REQUEST_METHOD

def test_REQUEST_METHOD_miss():
    # PEP 3333 says REQUEST_METHOD is mandatory
    environ = {}

    with pytest.raises(KeyError):
        _helpers.REQUEST_METHOD(environ)


def test_REQUEST_METHOD_hit():
    environ = {'REQUEST_METHOD': 'FOO'}

    result = _helpers.REQUEST_METHOD(environ)

    assert result == 'FOO'


def test_CONTENT_TYPE_miss():
    # PEP 3333 says CONTENT_TYPE is optional
    environ = {}

    result = _helpers.CONTENT_TYPE(environ)

    assert result == ''


def test_CONTENT_TYPE_hit():
    environ = {'CONTENT_TYPE': 'text/html'}

    result = _helpers.CONTENT_TYPE(environ)

    assert result == 'text/html'


def test_USER_AGENT_miss():
    environ = {}

    result = _helpers.USER_AGENT(environ)

    assert result is None


def test_USER_AGENT_hit():
    environ = {'HTTP_USER_AGENT': 'FOO'}

    result = _helpers.USER_AGENT(environ)

    assert result == 'FOO'


def test_AUTHORIZATION_miss():
    environ = {}

    result = _helpers.AUTHORIZATION(environ)

    assert result == ''


def test_AUTHORIZATION_hit():
    environ = {'HTTP_AUTHORIZATION': 'FOO'}

    result = _helpers.AUTHORIZATION(environ)

    assert result == 'FOO'


def test_get_cookies_no_cache_ok_header_value():
    environ = {'HTTP_COOKIE': 'qux=spam'}

    result = _helpers.get_cookies(environ)

    assert isinstance(result, http_cookies.SimpleCookie)
    assert len(result) == 1
    assert result['qux'].value == 'spam'
    assert environ['paste.cookies'] == (result, 'qux=spam')


def test_get_cookies_w_cache_miss():
    environ = {
        'HTTP_COOKIE': 'qux=spam',
        'paste.cookies': (object(), 'foo=bar'),
    }
    result = _helpers.get_cookies(environ)

    assert isinstance(result, http_cookies.SimpleCookie)

    assert len(result) == 1
    assert result['qux'].value == 'spam'
    assert environ['paste.cookies'] == (result, 'qux=spam')


def test_get_cookies_w_cache_hit():
    existing = http_cookies.SimpleCookie()
    existing['foo'] = 'bar'
    environ = {
        'HTTP_COOKIE': 'qux=spam',
        'paste.cookies': (existing, 'qux=spam'),
    }

    result = _helpers.get_cookies(environ)

    assert result is existing


def test_construct_url():
    environ = {
        'wsgi.url_scheme': 'http',
        'HTTP_HOST': 'example.com',
    }

    result = _helpers.construct_url(environ)

    assert result == 'http://example.com/'

def test_header_value_miss():
    headers = []

    result = _helpers.header_value(headers, 'nonesuch')

    assert result == ''

def test_header_value_simple():
    headers = [('simple', 'SIMPLE')]

    result = _helpers.header_value(headers, 'simple')

    assert result == 'SIMPLE'

def test_must_decode_non_string():
    foo = object()

    result = _helpers.must_decode(foo)

    assert result is foo

def test_must_decode_unicode():
    foo = u'foo'

    result = _helpers.must_decode(foo)

    assert result is foo

def test_must_decode_utf8():
    foo = b'b\xc3\xa2tard'

    result = _helpers.must_decode(foo)

    assert result == foo.decode('utf-8')


def test_must_decode_latin1():
    foo = b'b\xe2tard'

    result = _helpers.must_decode(foo)

    assert result == foo.decode('latin1')


def test_must_encode_non_string():
    foo = object()

    result = _helpers.must_encode(foo)

    assert result is foo


def test_must_encode_unicode():
    foo = u'foo'

    result = _helpers.must_encode(foo)

    assert result == foo.encode('utf-8')


def test_must_encode_utf8():
    foo = b'b\xc3\xa2tard'

    result = _helpers.must_encode(foo)

    assert result is foo


def test_must_encode_latin1():
    foo = b'b\xe2tard'

    result = _helpers.must_encode(foo)

    assert result is foo

