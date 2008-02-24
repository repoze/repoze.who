import os
import unittest

here = os.path.abspath(os.path.dirname(__file__))

class Base(unittest.TestCase):
    def _makeEnviron(self, kw=None):
        environ = {}
        environ['wsgi.version'] = (1,0)
        if kw is not None:
            environ.update(kw)
        return environ

class TestMiddleware(Base):
    def _getTargetClass(self):
        from repoze.pam.middleware import PluggableAuthenticationMiddleware
        return PluggableAuthenticationMiddleware

    def _makeOne(self,
                 app=None,
                 registry=None,
                 request_classifier=None,
                 response_classifier=None,
                 add_credentials=True
                 ):
        if registry is None:
            registry = {}
            from repoze.pam.interfaces import IAuthenticatorPlugin
            from repoze.pam.interfaces import IExtractorPlugin
            from repoze.pam.interfaces import IChallengerPlugin
            registry[IExtractorPlugin] = [ DummyExtractor() ]
            registry[IAuthenticatorPlugin] = [ DummyAuthenticator() ]
            registry[IChallengerPlugin] = [ DummyChallenger() ]
        if app is None:
            app = DummyApp()
        if request_classifier is None:
            request_classifier = DummyRequestClassifier()
        if response_classifier is None:
            response_classifier = DummyResponseClassifier()
        mw = self._getTargetClass()(app, registry, request_classifier,
                                    response_classifier, add_credentials)
        return mw

    def test_extract_success(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        creds = mw.extract(environ, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')

    def test_extract_fail(self):
        environ = self._makeEnviron()
        from repoze.pam.interfaces import IExtractorPlugin
        registry = {
            IExtractorPlugin:[DummyNoResultsExtractor()]
            }
        mw = self._makeOne(registry=registry)
        creds = mw.extract(environ, None)
        self.assertEqual(creds, {})

    def test_extract_success_skip_noresults(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IExtractorPlugin
        registry = {
            IExtractorPlugin:[DummyNoResultsExtractor(), DummyExtractor()]
            }
        mw = self._makeOne(registry=registry)
        creds = mw.extract(environ, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')

    def test_extract_success_firstwins(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IExtractorPlugin
        extractor1 = DummyExtractor({'login':'fred','password':'fred'})
        extractor2 = DummyExtractor({'login':'bob','password':'bob'})
        registry = {
            IExtractorPlugin:[extractor1, extractor2]
            }
        mw = self._makeOne(registry=registry)
        creds = mw.extract(environ, None)
        self.assertEqual(creds['login'], 'fred')
        self.assertEqual(creds['password'], 'fred')

    def test_extract_find_implicit_classifier(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IExtractorPlugin
        extractor1 = DummyExtractor({'login':'fred','password':'fred'})
        extractor1.classifiers = set(['nomatch'])
        extractor2 = DummyExtractor({'login':'bob','password':'bob'})
        registry = {
            IExtractorPlugin:[extractor1, extractor2]
            }
        mw = self._makeOne(registry=registry)
        creds = mw.extract(environ, None)
        self.assertEqual(creds['login'], 'bob')
        self.assertEqual(creds['password'], 'bob')

    def test_extract_find_explicit_classifier(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IExtractorPlugin
        extractor1 = DummyExtractor({'login':'fred','password':'fred'})
        extractor1.classifiers = set(['nomatch'])
        extractor2 = DummyExtractor({'login':'bob','password':'bob'})
        extractor2.classifiers = set(['match'])
        registry = {
            IExtractorPlugin:[extractor1, extractor2]
            }
        mw = self._makeOne(registry=registry)
        creds = mw.extract(environ, 'match')
        self.assertEqual(creds['login'], 'bob')
        self.assertEqual(creds['password'], 'bob')

    def test_authenticate_success(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        creds = {'login':'chris', 'password':'password'}
        userid = mw.authenticate(environ, creds, None)
        self.assertEqual(userid, 'chris')

    def test_authenticate_fail(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        creds = {'login':'chris', 'password':'password'}
        from repoze.pam.interfaces import IAuthenticatorPlugin
        registry = {
            IAuthenticatorPlugin:[DummyFailAuthenticator()]
            }
        mw = self._makeOne(registry=registry)
        userid = mw.authenticate(environ, creds, None)
        self.assertEqual(userid, None)

    def test_authenticate_success_skip_fail(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IAuthenticatorPlugin
        registry = {
            IAuthenticatorPlugin:[DummyFailAuthenticator(),DummyAuthenticator()]
            }
        mw = self._makeOne(registry=registry)
        creds = {'login':'chris', 'password':'password'}
        userid = mw.authenticate(environ, creds, None)
        self.assertEqual(userid, 'chris')

    def test_authenticate_success_firstwins(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IAuthenticatorPlugin
        registry = {
            IAuthenticatorPlugin:[DummyAuthenticator('chris_id1'),
                                  DummyAuthenticator('chris_id2')]
            }
        mw = self._makeOne(registry=registry)
        creds = {'login':'chris', 'password':'password'}
        userid = mw.authenticate(environ, creds, None)
        self.assertEqual(userid, 'chris_id1')

    def test_authenticate_find_implicit_classifier(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IAuthenticatorPlugin
        plugin1 = DummyAuthenticator('chris_id1')
        plugin1.classifiers = set(['nomatch'])
        plugin2 = DummyAuthenticator('chris_id2')
        registry = {
            IAuthenticatorPlugin:[plugin1, plugin2]
            }
        mw = self._makeOne(registry=registry)
        creds = {'login':'chris', 'password':'password'}
        userid = mw.authenticate(environ, creds, None)
        self.assertEqual(userid, 'chris_id2')

    def test_authenticate_find_explicit_classifier(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IAuthenticatorPlugin
        plugin1 = DummyAuthenticator('chris_id1')
        plugin1.classifiers = set(['nomatch'])
        plugin2 = DummyAuthenticator('chris_id2')
        plugin2.classifiers = set(['match'])
        registry = {
            IAuthenticatorPlugin:[plugin1, plugin2]
            }
        mw = self._makeOne(registry=registry)
        creds = {'login':'chris', 'password':'password'}
        userid = mw.authenticate(environ, creds, 'match')
        self.assertEqual(userid, 'chris_id2')

    def test_on_ingress_success_addcredentials(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        classification = mw.on_ingress(environ)
        self.assertEqual(classification, 'browser')
        self.assertEqual(environ['REMOTE_USER'], 'chris')
        self.assertEqual(environ['repoze.pam.credentials'],
                     {'login':'chris','password':'password','userid':'chris'})
        
    def test_on_ingress_success_noaddcredentials(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        mw.add_credentials = False
        classification = mw.on_ingress(environ)
        self.assertEqual(classification, 'browser')
        self.assertEqual(environ['REMOTE_USER'], 'chris')
        self.failIf(environ.has_key('repoze.pam.credentials'))


class TestBasicAuthPlugin(Base):
    def _getTargetClass(self):
        from repoze.pam.plugins.basicauth import BasicAuthPlugin
        return BasicAuthPlugin

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.pam.interfaces import IChallengerPlugin
        from repoze.pam.interfaces import IExtractorPlugin
        klass = self._getTargetClass()
        verifyClass(IChallengerPlugin, klass)
        verifyClass(IExtractorPlugin, klass)

    def test_challenge(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron()
        from paste.httpexceptions import HTTPUnauthorized
        self.assertRaises(HTTPUnauthorized, plugin.challenge, environ,
                          None, None, None)
        
    def test_extract_noauthinfo(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron()
        result = plugin.extract(environ)
        self.assertEqual(result, {})

    def test_extract_nonbasic(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Digest abc'})
        result = plugin.extract(environ)
        self.assertEqual(result, {})

    def test_extract_nonbasic(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Digest abc'})
        result = plugin.extract(environ)
        self.assertEqual(result, {})

    def test_extract_basic_badencoding(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic abc'})
        result = plugin.extract(environ)
        self.assertEqual(result, {})

    def test_extract_basic_badrepr(self):
        plugin = self._makeOne('realm')
        value = 'foo'.encode('base64')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic %s' % value})
        result = plugin.extract(environ)
        self.assertEqual(result, {})

    def test_extract_basic_ok(self):
        plugin = self._makeOne('realm')
        value = 'foo:bar'.encode('base64')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic %s' % value})
        result = plugin.extract(environ)
        self.assertEqual(result, {'login':'foo', 'password':'bar'})

    def test_factory(self):
        from repoze.pam.plugins.basicauth import make_plugin
        plugin = make_plugin({}, 'realm')
        self.assertEqual(plugin.realm, 'realm')
        
class TestHTPasswdPlugin(Base):
    def _getTargetClass(self):
        from repoze.pam.plugins.htpasswd import HTPasswdPlugin
        return HTPasswdPlugin

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.pam.interfaces import IAuthenticatorPlugin
        klass = self._getTargetClass()
        verifyClass(IAuthenticatorPlugin, klass)

    def test_authenticate_nocreds(self):
        from StringIO import StringIO
        io = StringIO()
        plugin = self._makeOne(io, None)
        environ = self._makeEnviron()
        creds = {}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, False)
        
    def test_authenticate_nolines(self):
        from StringIO import StringIO
        io = StringIO()
        plugin = self._makeOne(io, None)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, False)
        
    def test_authenticate_nousermatch(self):
        from StringIO import StringIO
        io = StringIO('nobody:foo')
        plugin = self._makeOne(io, None)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, False)

    def test_authenticate_match(self):
        from StringIO import StringIO
        io = StringIO('chrism:pass')
        def check(password, hashed):
            return True
        plugin = self._makeOne(io, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, True)

    def test_authenticate_badline(self):
        from StringIO import StringIO
        io = StringIO('badline\nchrism:pass')
        def check(password, hashed):
            return True
        plugin = self._makeOne(io, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, True)

    def test_authenticate_filename(self):
        htpasswd = os.path.join(here, 'fixtures', 'test.htpasswd')
        def check(password, hashed):
            return True
        plugin = self._makeOne(htpasswd, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, True)

    def test_check_crypted(self):
        from crypt import crypt
        salt = '123'
        hashed = crypt('password', salt)
        from repoze.pam.plugins.htpasswd import check_crypted
        self.assertEqual(check_crypted('password', hashed), True)
        self.assertEqual(check_crypted('notpassword', hashed), False)

    def test_factory(self):
        from repoze.pam.plugins.htpasswd import make_plugin
        from repoze.pam.plugins.htpasswd import check_crypted
        plugin = make_plugin({}, 'foo',
                             'repoze.pam.plugins.htpasswd:check_crypted')
        self.assertEqual(plugin.filename, 'foo')
        self.assertEqual(plugin.check, check_crypted)
        

class TestDefaultRequestClassifier(Base):
    def _getTargetClass(self):
        from repoze.pam.classifiers import DefaultRequestClassifier
        return DefaultRequestClassifier

    def _makeOne(self, *arg, **kw):
        classifier = self._getTargetClass()(*arg, **kw)
        return classifier

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.pam.interfaces import IRequestClassifier
        klass = self._getTargetClass()
        verifyClass(IRequestClassifier, klass)

    def test_classify_dav_method(self):
        classifier = self._makeOne()
        environ = self._makeEnviron({'REQUEST_METHOD':'COPY'})
        result = classifier(environ)
        self.assertEqual(result, 'dav')

    def test_classify_dav_useragent(self):
        classifier = self._makeOne()
        environ = self._makeEnviron({'HTTP_USER_AGENT':'WebDrive'})
        result = classifier(environ)
        self.assertEqual(result, 'dav')
        
    def test_classify_xmlpost(self):
        classifier = self._makeOne()
        environ = self._makeEnviron({'CONTENT_TYPE':'text/xml',
                                     'REQUEST_METHOD':'POST'})
        result = classifier(environ)
        self.assertEqual(result, 'xmlpost')

    def test_classify_browser(self):
        classifier = self._makeOne()
        environ = self._makeEnviron({'CONTENT_TYPE':'text/xml',
                                     'REQUEST_METHOD':'GET'})
        result = classifier(environ)
        self.assertEqual(result, 'browser')
    
class TestDefaultResponseClassifier(Base):
    def _getTargetClass(self):
        from repoze.pam.classifiers import DefaultResponseClassifier
        return DefaultResponseClassifier

    def _makeOne(self, *arg, **kw):
        classifier = self._getTargetClass()(*arg, **kw)
        return classifier

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.pam.interfaces import IResponseClassifier
        klass = self._getTargetClass()
        verifyClass(IResponseClassifier, klass)

    def test_classify(self):
        classifier = self._makeOne()
        result = classifier(None, 'dav', None, None)
        self.assertEqual(result, 'dav')

class DummyApp:
    def __call__(self, environ, start_response):
        return ['a']
    
class DummyRequestClassifier:
    def __call__(self, environ):
        return 'browser'

class DummyResponseClassifier:
    def __call__(self, environ, request_classification, headers, exception):
        return request_classification
    
class DummyExtractor:
    def __init__(self, credentials=None):
        if credentials is None:
            credentials = {'login':'chris', 'password':'password'}
        self.credentials = credentials
    def extract(self, environ):
        return self.credentials

class DummyNoResultsExtractor:
    def extract(self, environ):
        return {}
    
class DummyAuthenticator:
    def __init__(self, userid=None):
        self.userid = userid
        
    def authenticate(self, environ, credentials):
        if self.userid is None:
            return credentials['login']
        return self.userid

class DummyFailAuthenticator:
    def authenticate(self, environ, credentials):
        return None

class DummyChallenger:
    def challenge(self, environ, request_classifier, headers, exception):
        environ['challenged'] = True
