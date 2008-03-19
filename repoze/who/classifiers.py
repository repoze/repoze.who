from paste.httpheaders import USER_AGENT
from paste.httpheaders import REQUEST_METHOD
from paste.httpheaders import CONTENT_TYPE

import zope.interface
from repoze.who.interfaces import IRequestClassifier
from repoze.who.interfaces import IChallengeDecider

_DAV_METHODS = (
    'OPTIONS',
    'PROPFIND',
    'PROPPATCH',
    'MKCOL',
    'LOCK',
    'UNLOCK',
    'TRACE',
    'DELETE',
    'COPY',
    'MOVE'
    )

_DAV_USERAGENTS = (
    'Microsoft Data Access Internet Publishing Provider',
    'WebDrive',
    'Zope External Editor',
    'WebDAVFS',
    'Goliath',
    'neon',
    'davlib',
    'wsAPI',
    'Microsoft-WebDAV'
    )

@zope.interface.implementer(IRequestClassifier)
def default_request_classifier(environ):
    """ Returns one of the classifiers 'dav', 'xmlpost', or 'browser',
    depending on the imperative logic below"""
    request_method = REQUEST_METHOD(environ)
    if request_method in _DAV_METHODS:
        return 'dav'
    useragent = USER_AGENT(environ)
    if useragent:
        for agent in _DAV_USERAGENTS:
            if useragent.find(agent) != -1:
                return 'dav'
    if request_method == 'POST':
        if CONTENT_TYPE(environ) == 'text/xml':
            return 'xmlpost'
    return 'browser'

@zope.interface.implementer(IChallengeDecider)
def default_challenge_decider(environ, status, headers):
    if status.startswith('401 '):
        return True
    return False
