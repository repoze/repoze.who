import binascii

from paste.httpheaders import WWW_AUTHENTICATE
from paste.httpheaders import AUTHORIZATION
from paste.httpexceptions import HTTPUnauthorized

from zope.interface import implements

from repoze.pam.interfaces import IIdentifier
from repoze.pam.interfaces import IChallenger

class BasicAuthPlugin(object):

    implements(IIdentifier, IChallenger)
    
    def __init__(self, realm):
        self.realm = realm

    # IIdentifier
    def identify(self, environ):
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

    # IIdentifier
    def remember(self, environ, identity):
        # we need to do nothing here; the browser remembers the basic
        # auth info as a result of the user typing it in.
        pass

    def _get_wwwauth(self):
        head = WWW_AUTHENTICATE.tuples('Basic realm="%s"' % self.realm)
        return head

    # IIdentifier
    def forget(self, environ, identity):
        return self._get_wwwauth()

    # IChallenger
    def challenge(self, environ, status, app_headers, forget_headers):
        head = self._get_wwwauth()
        if head != forget_headers:
            head = head + forget_headers
        return HTTPUnauthorized(headers=head)

def make_plugin(pam_conf, realm='basic'):
    plugin = BasicAuthPlugin(realm)
    return plugin

