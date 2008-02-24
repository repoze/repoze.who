import binascii

from paste.httpheaders import WWW_AUTHENTICATE
from paste.httpheaders import AUTHORIZATION
from paste.httpexceptions import HTTPUnauthorized

from zope.interface import implements

from repoze.pam.interfaces import IChallengerPlugin
from repoze.pam.interfaces import IExtractorPlugin

class BasicAuthPlugin(object):

    implements(IChallengerPlugin, IExtractorPlugin)
    
    def __init__(self, realm):
        self.realm = realm

    # IChallengerPlugin
    def challenge(self, environ, request_classifier, headers, exception):
        head = WWW_AUTHENTICATE.tuples('Basic realm="%s"' % self.realm)
        raise HTTPUnauthorized(headers=head)

    # IExtractorPlugin
    def extract(self, environ):
        authorization = AUTHORIZATION(environ)
        try:
            authmeth, auth = authorization.split(' ', 1)
        except ValueError:
            # not enough values to unpack
            return {}
        if authmeth.lower() == 'basic':
            try:
                auth = auth.strip().decode('base64')
            except binascii.Error:
                # can't decode
                return {}
            try:
                login, password = auth.split(':', 1)
            except ValueError:
                # not enough values to unpack
                return {}

            return {'login':login, 'password':password}

        return {}

def make_plugin(pam_conf, realm='basic'):
    plugin = BasicAuthPlugin(realm)
    return plugin

