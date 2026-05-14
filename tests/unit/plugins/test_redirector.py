import io
from urllib import parse as urllib_parse

import pytest
from zope.interface import verify

from repoze.who import interfaces
from repoze.who.plugins import redirector

LOGIN_URL = 'http://example.com/login.html'

def _makeEnviron(path_info='/', identifier=None):
    if identifier is None:
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
    content_type, body = encode_multipart_formdata()
    environ = {
        'wsgi.version': (1,0),
        'wsgi.input': io.StringIO(body),
        'wsgi.url_scheme':'http',
        'SERVER_NAME': 'www.example.com',
        'SERVER_PORT': '80',
        'CONTENT_TYPE': content_type,
        'CONTENT_LENGTH': len(body),
        'REQUEST_METHOD': 'POST',
        'repoze.who.plugins': {'cookie': identifier},
        'QUERY_STRING': 'default=1',
        'PATH_INFO': path_info,
    }
    return environ


def test_rp_class_conforms_to_IChallenger():
    verify.verifyClass(interfaces.IChallenger, redirector.RedirectorPlugin)


def test_rp_instance_conforms_to_IChallenger():
    plugin = redirector.RedirectorPlugin(login_url=LOGIN_URL)
    verify.verifyObject(interfaces.IChallenger, plugin)


def test_rp_ctor_w_reason_param_wo_reason_header():
    with pytest.raises(redirector.BothReasonHeaderAndReasonParamOrNeither):
        redirector.RedirectorPlugin(
            LOGIN_URL,
            reason_param='reason',
            reason_header=None,
        )


def test_rp_ctor_wo_reason_param_w_reason_header():
    with pytest.raises(redirector.BothReasonHeaderAndReasonParamOrNeither):
        redirector.RedirectorPlugin(
            LOGIN_URL,
            reason_param=None,
            reason_header='X-Reason',
        )


def test_rp_challenge():
    plugin = redirector.RedirectorPlugin(
        LOGIN_URL,
        came_from_param='came_from',
        reason_param='reason',
        reason_header='X-Authorization-Failure-Reason',
    )
    environ = _makeEnviron()
    sr = DummyStartResponse()

    app = plugin.challenge(
        environ,
        '401 Unauthorized',
        [('app', '1')],
        [('forget', '1')],
    )

    result = b''.join(app(environ, sr)).decode('ascii')
    assert result.startswith('302 Found')

    assert sr.headers[0][0] == 'forget'
    assert sr.headers[0][1] == '1'
    assert sr.headers[1][0] == 'Location'

    url = sr.headers[1][1]
    parts = urllib_parse.urlparse(url)
    parts_qsl = urllib_parse.parse_qsl(parts[4])
    assert len(parts_qsl) == 1
    came_from_key, came_from_value = parts_qsl[0]
    assert parts[0] == 'http'
    assert parts[1] == 'example.com'
    assert parts[2] == '/login.html'
    assert parts[3] == ''
    assert came_from_key == 'came_from'
    assert came_from_value == 'http://www.example.com/?default=1'

    assert sr.headers[2][0] == 'Content-Length'
    assert sr.headers[2][1] == '165'
    assert sr.headers[3][0] == 'Content-Type'
    assert sr.headers[3][1] == 'text/plain; charset=UTF-8'
    assert sr.status == '302 Found'


def test_rp_challenge_with_reason_header():
    plugin = redirector.RedirectorPlugin(
        LOGIN_URL,
        came_from_param='came_from',
        reason_param='reason',
        reason_header='X-Authorization-Failure-Reason',
    )
    environ = _makeEnviron()
    sr = DummyStartResponse()

    app = plugin.challenge(
        environ,
        '401 Unauthorized',
        [('X-Authorization-Failure-Reason', 'you are ugly')],
        [('forget', '1')]
    )

    result = b''.join(app(environ, sr)).decode('ascii')
    assert result.startswith('302 Found')

    assert sr.headers[1][0] == 'Location'
    url = sr.headers[1][1]
    parts = urllib_parse.urlparse(url)
    parts_qsl = urllib_parse.parse_qsl(parts[4])
    assert len(parts_qsl) == 2
    parts_qsl.sort()
    came_from_key, came_from_value = parts_qsl[0]
    reason_key, reason_value = parts_qsl[1]
    assert parts[0] == 'http'
    assert parts[1] == 'example.com'
    assert parts[2] == '/login.html'
    assert parts[3] == ''
    assert came_from_key == 'came_from'
    assert came_from_value == 'http://www.example.com/?default=1'
    assert reason_key == 'reason'
    assert reason_value == 'you are ugly'


def test_rp_challenge_with_custom_reason_header():
    plugin = redirector.RedirectorPlugin(
        LOGIN_URL,
        came_from_param='came_from',
        reason_param='reason',
        reason_header='X-Custom-Auth-Failure',
    )
    environ = _makeEnviron()
    environ['came_from'] = 'http://example.com/came_from'
    sr = DummyStartResponse()

    app = plugin.challenge(
        environ,
        '401 Unauthorized',
        [('X-Authorization-Failure-Reason', 'you are ugly')],
        [('forget', '1')])

    result = b''.join(app(environ, sr)).decode('ascii')
    assert result.startswith('302 Found')

    assert sr.headers[1][0] == 'Location'
    url = sr.headers[1][1]
    parts = urllib_parse.urlparse(url)
    parts_qsl = urllib_parse.parse_qsl(parts[4])
    assert len(parts_qsl) == 1
    came_from_key, came_from_value = parts_qsl[0]
    assert parts[0] == 'http'
    assert parts[1] == 'example.com'
    assert parts[2] == '/login.html'
    assert parts[3] == ''
    assert came_from_key == 'came_from'
    assert came_from_value == 'http://www.example.com/?default=1'


def test_rp_challenge_w_reason_no_reason_param_no_came_from_param():
    plugin = redirector.RedirectorPlugin(
        LOGIN_URL,
        came_from_param=None,
        reason_param=None,
        reason_header=None,
    )
    environ = _makeEnviron()
    sr = DummyStartResponse()

    app = plugin.challenge(
        environ,
        '401 Unauthorized',
        [('X-Authorization-Failure-Reason', 'you are ugly')],
        [('forget', '1')]
    )

    result = b''.join(app(environ, sr)).decode('ascii')
    assert result.startswith('302 Found')

    assert sr.headers[0][0] == "forget"
    assert sr.headers[0][1] == "1"
    assert sr.headers[1][0] == 'Location'
    url = sr.headers[1][1]
    parts = urllib_parse.urlparse(url)
    parts_qsl = urllib_parse.parse_qsl(parts[4])
    assert len(parts_qsl) == 0
    assert parts[0] == 'http'
    assert parts[1] == 'example.com'
    assert parts[2] == '/login.html'
    assert parts[3] == ''


def test_rp_challenge_w_reason_no_reason_param_w_came_from_param():
    plugin = redirector.RedirectorPlugin(
        LOGIN_URL,
        came_from_param='came_from',
        reason_param=None,
        reason_header=None,
    )
    environ = _makeEnviron()
    environ['came_from'] = 'http://example.com/came_from'

    app = plugin.challenge(
        environ,
        '401 Unauthorized',
        [('X-Authorization-Failure-Reason', 'you are ugly')],
        [('forget', '1')],
    )

    sr = DummyStartResponse()
    result = b''.join(app(environ, sr)).decode('ascii')
    assert result.startswith('302 Found')
    assert sr.headers[1][0] == 'Location'
    url = sr.headers[1][1]
    parts = urllib_parse.urlparse(url)
    parts_qsl = urllib_parse.parse_qsl(parts[4])
    assert len(parts_qsl) == 1
    came_from_key, came_from_value = parts_qsl[0]
    assert parts[0] == 'http'
    assert parts[1] == 'example.com'
    assert parts[2] == '/login.html'
    assert parts[3] == ''
    assert came_from_key == 'came_from'
    assert came_from_value == 'http://www.example.com/?default=1'


def test_rp_challenge_with_reason_and_custom_reason_param():
    plugin = redirector.RedirectorPlugin(
        LOGIN_URL,
        came_from_param='came_from',
        reason_param='auth_failure',
        reason_header='X-Custom-Auth-Failure',
    )
    environ = _makeEnviron()
    sr = DummyStartResponse()

    app = plugin.challenge(
        environ,
        '401 Unauthorized',
        [
            ('X-Authorization-Failure-Reason', 'wrong reason'),
            ('X-Custom-Auth-Failure', 'you are ugly'),
        ],
        [('forget', '1')],
    )

    result = b''.join(app(environ, sr)).decode('ascii')
    assert result.startswith('302 Found')

    assert sr.headers[1][0] == 'Location'
    url = sr.headers[1][1]
    parts = urllib_parse.urlparse(url)
    parts_qsl = urllib_parse.parse_qsl(parts[4])
    assert len(parts_qsl) == 2
    parts_qsl.sort()
    reason_key, reason_value = parts_qsl[0]
    came_from_key, came_from_value = parts_qsl[1]
    assert parts[0] == 'http'
    assert parts[1] == 'example.com'
    assert parts[2] == '/login.html'
    assert parts[3] == ''
    assert came_from_key == 'came_from'
    assert came_from_value == 'http://www.example.com/?default=1'
    assert reason_key == 'auth_failure'
    assert reason_value == 'you are ugly'


def test_rp_challenge_wo_reason_w_came_from_param():
    plugin = redirector.RedirectorPlugin(
        LOGIN_URL,
        came_from_param='came_from',
    )
    environ = _makeEnviron()
    sr = DummyStartResponse()

    app = plugin.challenge(
        environ,
        '401 Unauthorized',
        [],
        [('forget', '1')],
    )

    result = b''.join(app(environ, sr)).decode('ascii')
    assert result.startswith('302 Found')

    assert sr.headers[1][0] == 'Location'
    url = sr.headers[1][1]
    parts = urllib_parse.urlparse(url)
    parts_qsl = urllib_parse.parse_qsl(parts[4])
    assert len(parts_qsl) == 1
    came_from_key, came_from_value = parts_qsl[0]
    assert parts[0] == 'http'
    assert parts[1] == 'example.com'
    assert parts[2] == '/login.html'
    assert parts[3] == ''
    assert came_from_key == 'came_from'
    assert came_from_value == 'http://www.example.com/?default=1'


def test_rp_challenge_with_setcookie_from_app():
    plugin = redirector.RedirectorPlugin(
        LOGIN_URL,
        came_from_param='came_from',
        reason_param='reason',
        reason_header='X-Authorization-Failure-Reason',
    )
    environ = _makeEnviron()
    sr = DummyStartResponse()

    app = plugin.challenge(
        environ,
        '401 Unauthorized',
        [
            ('app', '1'),
            ('set-cookie','a'),
            ('set-cookie','b'),
        ],
        [],
    )

    result = b''.join(app(environ, sr)).decode('ascii')
    assert result.startswith('302 Found')

    assert sr.headers[0][0] == 'set-cookie'
    assert sr.headers[0][1] == 'a'
    assert sr.headers[1][0] == 'set-cookie'
    assert sr.headers[1][1] == 'b'


def test_mrp_wo_login_url_raises():
    with pytest.raises(redirector.LoginUrlRequired):
        redirector.make_plugin(None)


def test_mrp_w_reason_header_wo_reason_param_raises():
    with pytest.raises(redirector.BothReasonHeaderAndReasonParamOrNeither):
        redirector.make_plugin('/go_there', reason_header='X-Reason')


def test_mrp_defaults():
    plugin = redirector.make_plugin('/go_there')

    assert plugin.login_url == '/go_there'
    assert plugin.came_from_param is None
    assert plugin.reason_param is None
    assert plugin.reason_header is None


def test_mrp_w_explicit_came_from_param():
    plugin = redirector.make_plugin('/go_there', came_from_param='whence')

    assert plugin.login_url == '/go_there'
    assert plugin.came_from_param == 'whence'
    assert plugin.reason_param is None
    assert plugin.reason_header is None


def test_mrp_w_explicit_reason_param():
    plugin = redirector.make_plugin('/go_there', reason_param='why')

    assert plugin.login_url == '/go_there'
    assert plugin.came_from_param is None
    assert plugin.reason_param == 'why'
    assert plugin.reason_header == 'X-Authorization-Failure-Reason'


def test_mrp_w_explicit_reason_header_param():
    plugin = redirector.make_plugin(
        '/go_there',
        reason_param='why',
        reason_header='X-Reason',
    )
    assert plugin.login_url == '/go_there'
    assert plugin.came_from_param is None
    assert plugin.reason_param == 'why'
    assert plugin.reason_header == 'X-Reason'


class DummyIdentifier:
    forgotten = False
    remembered = False

    def __init__(self, credentials=None, remember_headers=None,
                 forget_headers=None, replace_app=None):
        self.credentials = credentials
        self.remember_headers = remember_headers
        self.forget_headers = forget_headers
        self.replace_app = replace_app

class DummyStartResponse:
    def __call__(self, status, headers, exc_info=None):
        self.status = status
        self.headers = headers
        self.exc_info = exc_info
        return []

def encode_multipart_formdata():
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = f'multipart/form-data; boundary={BOUNDARY}'
    return content_type, body
