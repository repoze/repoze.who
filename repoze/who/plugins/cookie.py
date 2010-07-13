import binascii

from paste.request import get_cookies

from zope.interface import implements

from repoze.who.interfaces import IIdentifier

class InsecureCookiePlugin(object):

    implements(IIdentifier)
    
    def __init__(self, cookie_name, cookie_path='/', charset=None):
        self.cookie_name = cookie_name
        self.cookie_path = cookie_path
        self.charset = charset

    # IIdentifier
    def identify(self, environ):
        cookies = get_cookies(environ)
        cookie = cookies.get(self.cookie_name)

        if cookie is None:
            return None

        try:
            auth = cookie.value.decode('base64')
        except binascii.Error: # can't decode
            return None

        try:
            login, password = auth.split(':', 1)
            if self.charset is not None:
                login = login.decode(self.charset)
                password = password.decode(self.charset)
            return {'login':login, 'password':password}
        except ValueError: # not enough values to unpack
            return None

    # IIdentifier
    def forget(self, environ, identity):
        # return a expires Set-Cookie header
        expired = ('%s=""; Path=%s; Expires=Sun, 10-May-1971 11:59:00 GMT' %
                   (self.cookie_name, self.cookie_path))
        return [('Set-Cookie', expired)]
    
    # IIdentifier
    def remember(self, environ, identity):
        login = identity['login']
        password = identity['password']
        if self.charset is not None:
            login = login.encode(self.charset)
            password = password.encode(self.charset)
        cookie_value = '%s:%s' % (login, password)
        cookie_value = cookie_value.encode('base64').rstrip()
        cookies = get_cookies(environ)
        existing = cookies.get(self.cookie_name)
        value = getattr(existing, 'value', None)
        if value != cookie_value:
            # return a Set-Cookie header
            set_cookie = '%s=%s; Path=%s;' % (self.cookie_name, cookie_value,
                                              self.cookie_path)
            return [('Set-Cookie', set_cookie)]

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__,
                            id(self)) #pragma NO COVERAGE

def make_plugin(cookie_name='repoze.who.plugins.cookie',
                cookie_path='/',
                charset=None):
    plugin = InsecureCookiePlugin(cookie_name, cookie_path, charset)
    return plugin

