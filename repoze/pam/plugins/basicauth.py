import binascii

from paste.httpheaders import WWW_AUTHENTICATE
from paste.httpheaders import AUTHORIZATION
from paste.httpexceptions import HTTPUnauthorized

from zope.interface import implements

from repoze.pam.interfaces import IChallengerPlugin
from repoze.pam.interfaces import IExtractorPlugin
from repoze.pam.interfaces import IPostExtractorPlugin

class BasicAuthPlugin(object):

    implements(IChallengerPlugin, IExtractorPlugin, IPostExtractorPlugin)
    
    def __init__(self, realm):
        self.realm = realm

    # IChallengerPlugin
    def challenge(self, environ, status, headers):
        if status == '401 Unauthorized':
            headers = WWW_AUTHENTICATE.tuples('Basic realm="%s"' % self.realm)
            return HTTPUnauthorized(headers=headers)

    # IExtractorPlugin
    def extract(self, environ):
        authorization = AUTHORIZATION(environ)
        try:
            authmeth, auth = authorization.split(' ', 1)
        except ValueError: # not enough values to unpack
            return {}
        if authmeth.lower() == 'basic':
            try:
                auth = auth.strip().decode('base64')
            except binascii.Error: # can't decode
                return {}
            try:
                login, password = auth.split(':', 1)
            except ValueError: # not enough values to unpack
                return {}
            auth = {'login':login, 'password':password}
            return auth

        return {}

    # IPostExtractorPlugin
    def post_extract(self, environ, credentials, extractor):
        if credentials:
            if not AUTHORIZATION(environ):
                auth = '%(login)s:%(password)s' % credentials
                auth = auth.encode('base64').rstrip()
                header = 'Basic %s' % auth
                environ['HTTP_AUTHORIZATION'] = header

def make_plugin(pam_conf, realm='basic'):
    plugin = BasicAuthPlugin(realm)
    return plugin

