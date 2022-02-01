import base64
import http.cookies
import wsgiref.util
import wsgiref.headers

def encodestring(value):
    return base64.encodebytes(bytes(value, 'ascii')).decode('ascii')

def REQUEST_METHOD(environ):
    return environ['REQUEST_METHOD']

def CONTENT_TYPE(environ):
    return environ.get('CONTENT_TYPE', '')

def USER_AGENT(environ):
    return environ.get('HTTP_USER_AGENT')

def AUTHORIZATION(environ):
    return environ.get('HTTP_AUTHORIZATION', '')

def get_cookies(environ):
    header = environ.get('HTTP_COOKIE', '')
    if 'paste.cookies' in environ:
        cookies, check_header = environ['paste.cookies']
        if check_header == header:
            return cookies
    cookies = http.cookies.SimpleCookie()
    try:
        cookies.load(header)
    except http.cookies.CookieError: #pragma NO COVER (can't see how to provoke this)
        pass
    environ['paste.cookies'] = (cookies, header)
    return cookies

def construct_url(environ):
    return wsgiref.util.request_uri(environ)

def header_value(environ, key):
    headers = wsgiref.headers.Headers(environ)
    values = headers.get(key)
    return values or ""

def must_decode(value):
    if type(value) is bytes:
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            return value.decode('latin1')
    return value

def must_encode(value):
    if type(value) is str:
        return value.encode('utf-8')
    return value
