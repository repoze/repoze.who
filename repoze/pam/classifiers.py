from paste.httpheaders import USER_AGENT
from paste.httpheaders import REQUEST_METHOD
from paste.httpheaders import CONTENT_TYPE

from zope.interface import implements

from repoze.pam.interfaces import IRequestClassifier
from repoze.pam.interfaces import IResponseClassifier

class DefaultRequestClassifier(object):
    implements(IRequestClassifier)

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

    _DAV_USERAGENTS = ( # convenience, override as necessary
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

    def __call__(self, environ):
        """ Returns one of the classifiers 'dav', 'xmlpost', or
        'browser', depending on the imperative logic below"""
        request_method = REQUEST_METHOD(environ)
        if request_method in self._DAV_METHODS:
            return 'dav'
        useragent = USER_AGENT(environ)
        if useragent:
            for agent in self._DAV_USERAGENTS:
                if useragent.find(agent) != -1:
                    return 'dav'
        if request_method == 'POST':
            if CONTENT_TYPE(environ) == 'text/xml':
                return 'xmlpost'
        return 'browser'
    
class DefaultResponseClassifier(object):
    implements(IResponseClassifier)
    def __call__(self, environ, request_classification, headers, exception):
        """ By default, return the request classification """
        return request_classification
    
