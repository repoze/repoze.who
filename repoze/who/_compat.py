import wsgiref.util
import wsgiref.headers
try:
    from Cookie import SimpleCookie
    from Cookie import CookieError
except ImportError: #pragma NO COVER Python >= 3.0
    from http.cookies import SimpleCookie
    from http.cookies import CookieError

try:
    STRING_TYPES = (str, unicode)
except NameError:
    STRING_TYPES = (str,)

def REQUEST_METHOD(environ):
    return environ['REQUEST_METHOD']

def CONTENT_TYPE(environ):
    return environ['CONTENT_TYPE']

def USER_AGENT(environ):
    return environ.get('HTTP_USER_AGENT')

def AUTHORIZATION(environ):
    return environ.get('HTTP_AUTHORIZATION', '')

def get_cookies(environ):
    header = environ.get('HTTP_COOKIE', '')
    if environ.has_key('paste.cookies'):
        cookies, check_header = environ['paste.cookies']
        if check_header == header:
            return cookies
    cookies = SimpleCookie()
    try:
        cookies.load(header)
    except CookieError:
        pass
    environ['paste.cookies'] = (cookies, header)
    return cookies

def construct_url(environ):
    return wsgiref.util.request_uri(environ)

def header_value(environ, key):
    headers = wsgiref.headers.Headers(environ)
    values = headers.get(key)
    if not values:
        return ""
    if isinstance(values, list):
        return ",".join(values)
    else:
        return values
