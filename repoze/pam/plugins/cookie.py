import binascii

from paste.request import get_cookies

from zope.interface import implements

from repoze.pam.interfaces import IExtractorPlugin
from repoze.pam.interfaces import IPostExtractorPlugin

class InsecureCookiePlugin(object):

    implements(IExtractorPlugin, IPostExtractorPlugin)
    
    def __init__(self, cookie_name):
        self.cookie_name = cookie_name

    # IExtractorPlugin
    def extract(self, environ):
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

    # IPostExtractorPlugin
    def post_extract(self, environ, credentials, extractor):
        if credentials:
            cookie_value = '%(login)s:%(password)s' % credentials
            cookie_value = cookie_value.encode('base64').rstrip()
            cookies = get_cookies(environ)
            existing = cookies.get(self.cookie_name)
            value = getattr(existing, 'value', None)
            if value != cookie_value:
                # go ahead and set it in the environment for downstream
                # apps to consume (XXX?)
                cookies[self.cookie_name] = cookie_value
                output = cookies.output(header='', sep='').lstrip()
                environ['HTTP_COOKIE'] = output
                # return a Set-Cookie header
                set_cookie = '%s=%s; Path=/;' % (self.cookie_name, cookie_value)
                return [('Set-Cookie', set_cookie)]

def make_plugin(pam_conf, cookie_name='repoze.pam.plugins.cookie'):
    plugin = InsecureCookiePlugin(cookie_name)
    return plugin

