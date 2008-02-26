import binascii

from paste.request import get_cookies

from zope.interface import implements

from repoze.pam.interfaces import IIdentifier

class InsecureCookiePlugin(object):

    implements(IIdentifier)
    
    def __init__(self, cookie_name):
        self.cookie_name = cookie_name

    # IIdentifier
    def identify(self, environ):
        cookies = get_cookies(environ)
        cookie = cookies.get(self.cookie_name)

        if cookie is None:
            return {}

        try:
            auth = cookie.value.decode('base64')
        except binascii.Error: # can't decode
            return {}

        try:
            login, password = auth.split(':', 1)
            return {'login':login, 'password':password}
        except ValueError: # not enough values to unpack
            return {}

    # IIdentifier
    def forget(self, environ, identity):
        # return a expires Set-Cookie header
        expired = ('%s=""; Path=/; Expires=Sun, 10-May-1971 11:59:00 GMT' %
                   self.cookie_name)
        return [('Set-Cookie', expired)]
    
    # IIdentifier
    def remember(self, environ, identity):
        cookie_value = '%(login)s:%(password)s' % identity
        cookie_value = cookie_value.encode('base64').rstrip()
        cookies = get_cookies(environ)
        existing = cookies.get(self.cookie_name)
        value = getattr(existing, 'value', None)
        if value != cookie_value:
            # return a Set-Cookie header
            set_cookie = '%s=%s; Path=/;' % (self.cookie_name, cookie_value)
            return [('Set-Cookie', set_cookie)]

def make_plugin(pam_conf, cookie_name='repoze.pam.plugins.cookie'):
    plugin = InsecureCookiePlugin(cookie_name)
    return plugin

