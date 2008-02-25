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
        creds, plugin = mw.extract(environ, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.failIf(plugin is None)

    def test_extract_fail(self):
        environ = self._makeEnviron()
        from repoze.pam.interfaces import IExtractorPlugin
        extractor = DummyNoResultsExtractor()
        registry = {
            IExtractorPlugin:[extractor]
            }
        mw = self._makeOne(registry=registry)
        creds, plugin = mw.extract(environ, None)
        self.assertEqual(creds, {})
        self.assertEqual(plugin, None)

    def test_extract_success_skip_noresults(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IExtractorPlugin
        extractor1 = DummyNoResultsExtractor()
        extractor2 = DummyExtractor() 
        registry = {
            IExtractorPlugin:[extractor1, extractor2]
            }
        mw = self._makeOne(registry=registry)
        creds, plugin = mw.extract(environ, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(plugin, extractor2)

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
        creds, plugin = mw.extract(environ, None)
        self.assertEqual(creds['login'], 'fred')
        self.assertEqual(creds['password'], 'fred')
        self.assertEqual(plugin, extractor1)

    def test_extract_find_implicit_classifier(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IExtractorPlugin
        extractor1 = DummyExtractor({'login':'fred','password':'fred'})
        extractor1.request_classifications = set(['nomatch'])
        extractor2 = DummyExtractor({'login':'bob','password':'bob'})
        registry = {
            IExtractorPlugin:[extractor1, extractor2]
            }
        mw = self._makeOne(registry=registry)
        creds, plugin = mw.extract(environ, None)
        self.assertEqual(creds['login'], 'bob')
        self.assertEqual(creds['password'], 'bob')
        self.assertEqual(plugin, extractor2)

    def test_extract_find_explicit_classifier(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IExtractorPlugin
        extractor1 = DummyExtractor({'login':'fred','password':'fred'})
        extractor1.request_classifications = set(['nomatch'])
        extractor2 = DummyExtractor({'login':'bob','password':'bob'})
        extractor2.request_classifications = set(['match'])
        registry = {
            IExtractorPlugin:[extractor1, extractor2]
            }
        mw = self._makeOne(registry=registry)
        creds, plugin = mw.extract(environ, 'match')
        self.assertEqual(creds['login'], 'bob')
        self.assertEqual(creds['password'], 'bob')
        self.assertEqual(plugin, extractor2)

    def test_authenticate_success(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        creds = {'login':'chris', 'password':'password'}
        userid, plugin = mw.authenticate(environ, creds, None)
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
        userid, plugin = mw.authenticate(environ, creds, None)
        self.assertEqual(userid, None)
        self.assertEqual(plugin, None)

    def test_authenticate_success_skip_fail(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IAuthenticatorPlugin
        plugin1 = DummyFailAuthenticator()
        plugin2 = DummyAuthenticator()
        registry = {
            IAuthenticatorPlugin:[plugin1, plugin2]
            }
        mw = self._makeOne(registry=registry)
        creds = {'login':'chris', 'password':'password'}
        userid, plugin = mw.authenticate(environ, creds, None)
        self.assertEqual(userid, 'chris')
        self.assertEqual(plugin, plugin2)

    def test_authenticate_success_firstwins(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IAuthenticatorPlugin
        plugin1 = DummyAuthenticator('chris_id1')
        plugin2 = DummyAuthenticator('chris_id2')
        registry = {
            IAuthenticatorPlugin:[plugin1, plugin2]
            }
        mw = self._makeOne(registry=registry)
        creds = {'login':'chris', 'password':'password'}
        userid, plugin = mw.authenticate(environ, creds, None)
        self.assertEqual(userid, 'chris_id1')
        self.assertEqual(plugin, plugin1)

    def test_authenticate_find_implicit_classifier(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IAuthenticatorPlugin
        plugin1 = DummyAuthenticator('chris_id1')
        plugin1.request_classifications = set(['nomatch'])
        plugin2 = DummyAuthenticator('chris_id2')
        registry = {
            IAuthenticatorPlugin:[plugin1, plugin2]
            }
        mw = self._makeOne(registry=registry)
        creds = {'login':'chris', 'password':'password'}
        userid, plugin = mw.authenticate(environ, creds, None)
        self.assertEqual(userid, 'chris_id2')
        self.assertEqual(plugin, plugin2)

    def test_authenticate_find_explicit_classifier(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        from repoze.pam.interfaces import IAuthenticatorPlugin
        plugin1 = DummyAuthenticator('chris_id1')
        plugin1.request_classifications = set(['nomatch'])
        plugin2 = DummyAuthenticator('chris_id2')
        plugin2.request_classifications = set(['match'])
        registry = {
            IAuthenticatorPlugin:[plugin1, plugin2]
            }
        mw = self._makeOne(registry=registry)
        creds = {'login':'chris', 'password':'password'}
        userid, plugin = mw.authenticate(environ, creds, 'match')
        self.assertEqual(userid, 'chris_id2')
        self.assertEqual(plugin, plugin2)

    def test_modify_environment_success_addcredentials(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        classification, headers = mw.modify_environment(environ)
        self.assertEqual(classification, 'browser')
        self.assertEqual(environ['REMOTE_USER'], 'chris')
        self.assertEqual(environ['repoze.pam.credentials'],
                         {'login':'chris','password':'password'})
        self.assertEqual(headers, [])
        
    def test_modify_environment_noaddcredentials(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        mw.add_credentials = False
        classification, headers = mw.modify_environment(environ)
        self.assertEqual(classification, 'browser')
        self.assertEqual(environ['REMOTE_USER'], 'chris')
        self.failIf(environ.has_key('repoze.pam.credentials'))
        self.assertEqual(headers, [])

    def test_modify_environment_nocredentials(self):
        environ = self._makeEnviron()
        from repoze.pam.interfaces import IExtractorPlugin
        registry = {
            IExtractorPlugin:[DummyNoResultsExtractor()],
            }
        mw = self._makeOne(registry=registry)
        classification, headers = mw.modify_environment(environ)
        self.assertEqual(classification, 'browser')
        self.assertEqual(environ.get('REMOTE_USER'), None)
        self.assertEqual(environ['repoze.pam.credentials'], {})
        self.assertEqual(headers, [])

    def test_modify_environment_remoteuser_already_set(self):
        environ = self._makeEnviron({'REMOTE_USER':'admin'})
        mw = self._makeOne()
        classification, headers = mw.modify_environment(environ)
        self.assertEqual(classification, 'browser')
        self.assertEqual(environ.get('REMOTE_USER'), 'admin')
        self.assertEqual(environ['repoze.pam.credentials'],
                         {'login':'chris', 'password':'password'})
        self.assertEqual(headers, [])

    def test_modify_environment_with_postextractor(self):
        environ = self._makeEnviron({'REMOTE_USER':'admin'})
        from repoze.pam.interfaces import IExtractorPlugin
        from repoze.pam.interfaces import IPostExtractorPlugin
        registry = {
            IExtractorPlugin:[DummyExtractor()],
            IPostExtractorPlugin:[DummyPostExtractor()],
            }
        mw = self._makeOne(registry=registry)
        classification, headers = mw.modify_environment(environ)
        self.assertEqual(classification, 'browser')
        self.assertEqual(environ.get('REMOTE_USER'), 'admin')
        self.assertEqual(environ['repoze.pam.credentials'],
                         {'login':'chris', 'password':'password'})
        self.assertEqual(headers, [('foo', 'bar')])
        
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

    def test_challenge_non401(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron()
        result = plugin.challenge(environ, '200 OK', {})
        self.assertEqual(result, None)

    def test_challenge_401(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron()
        result = plugin.challenge(environ, '401 Unauthorized', {})
        self.assertNotEqual(result, None)
        app_iter = result(environ, lambda *arg: None)
        items = []
        for item in app_iter:
            items.append(item)
        response = ''.join(items)
        self.failUnless(response.startswith('401 Unauthorized'))
        
    def test_extract_noauthinfo(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron()
        creds = plugin.extract(environ)
        self.assertEqual(creds, {})

    def test_extract_nonbasic(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Digest abc'})
        creds = plugin.extract(environ)
        self.assertEqual(creds, {})

    def test_extract_basic_badencoding(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic abc'})
        creds = plugin.extract(environ)
        self.assertEqual(creds, {})

    def test_extract_basic_badrepr(self):
        plugin = self._makeOne('realm')
        value = 'foo'.encode('base64')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic %s' % value})
        creds = plugin.extract(environ)
        self.assertEqual(creds, {})

    def test_extract_basic_ok(self):
        plugin = self._makeOne('realm')
        value = 'foo:bar'.encode('base64')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic %s' % value})
        creds = plugin.extract(environ)
        self.assertEqual(creds, {'login':'foo', 'password':'bar'})

    def test_post_extract_nocreds(self):
        plugin = self._makeOne('realm')
        creds = {}
        environ = self._makeEnviron()
        result = plugin.post_extract(environ, creds, plugin)
        self.assertEqual(result, None)
        self.assertEqual(environ.get('HTTP_AUTHORIZATION'), None)

    def test_post_extract_creds_withauthorization(self):
        plugin = self._makeOne('realm')
        creds = {'login':'foo', 'password':'password'}
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic foo'})
        result = plugin.post_extract(environ, creds, plugin)
        self.assertEqual(result, None)
        self.assertEqual(environ['HTTP_AUTHORIZATION'], 'Basic foo')

    def test_post_extract_creds_mutates(self):
        plugin = self._makeOne('realm')
        creds = {'login':'foo', 'password':'password'}
        environ = self._makeEnviron()
        result = plugin.post_extract(environ, creds, plugin)
        self.assertEqual(result, None)
        auth = 'foo:password'.encode('base64').rstrip()
        auth = 'Basic ' + auth
        self.assertEqual(environ['HTTP_AUTHORIZATION'], auth)
        
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

    def test_crypt_check(self):
        from crypt import crypt
        salt = '123'
        hashed = crypt('password', salt)
        from repoze.pam.plugins.htpasswd import crypt_check
        self.assertEqual(crypt_check('password', hashed), True)
        self.assertEqual(crypt_check('notpassword', hashed), False)

    def test_factory(self):
        from repoze.pam.plugins.htpasswd import make_plugin
        from repoze.pam.plugins.htpasswd import crypt_check
        plugin = make_plugin({}, 'foo',
                             'repoze.pam.plugins.htpasswd:crypt_check')
        self.assertEqual(plugin.filename, 'foo')
        self.assertEqual(plugin.check, crypt_check)


class TestInsecureCookiePlugin(Base):
    def _getTargetClass(self):
        from repoze.pam.plugins.cookie import InsecureCookiePlugin
        return InsecureCookiePlugin

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.pam.interfaces import IExtractorPlugin
        from repoze.pam.interfaces import IPostExtractorPlugin
        klass = self._getTargetClass()
        verifyClass(IExtractorPlugin, klass)
        verifyClass(IPostExtractorPlugin, klass)

    def test_extract_nocookies(self):
        plugin = self._makeOne('oatmeal')
        environ = self._makeEnviron()
        result = plugin.extract(environ)
        self.assertEqual(result, {})
        
    def test_extract_badcookies(self):
        plugin = self._makeOne('oatmeal')
        environ = self._makeEnviron({'HTTP_COOKIE':'oatmeal=a'})
        result = plugin.extract(environ)
        self.assertEqual(result, {})

    def test_extract_badcookies(self):
        plugin = self._makeOne('oatmeal')
        environ = self._makeEnviron({'HTTP_COOKIE':'oatmeal=a'})
        result = plugin.extract(environ)
        self.assertEqual(result, {})
    
    def test_extract_success(self):
        plugin = self._makeOne('oatmeal')
        auth = 'foo:password'.encode('base64').rstrip()
        environ = self._makeEnviron({'HTTP_COOKIE':'oatmeal=%s;' % auth})
        result = plugin.extract(environ)
        self.assertEqual(result, {'login':'foo', 'password':'password'})

    def test_post_extract_nocreds(self):
        plugin = self._makeOne('oatmeal')
        creds = {}
        environ = self._makeEnviron()
        result = plugin.post_extract(environ, creds, plugin)
        self.assertEqual(result, None)
        self.assertEqual(environ.get('HTTP_COOKIE'), None)

    def test_post_extract_creds_same(self):
        plugin = self._makeOne('oatmeal')
        creds = {'login':'foo', 'password':'password'}
        auth = 'foo:password'.encode('base64').rstrip()
        auth = 'oatmeal=%s;' % auth
        environ = self._makeEnviron({'HTTP_COOKIE':auth})
        result = plugin.post_extract(environ, creds, plugin)
        self.assertEqual(result, None)
        self.assertEqual(environ.get('HTTP_COOKIE'), auth)

    def test_post_extract_creds_different(self):
        plugin = self._makeOne('oatmeal')
        creds = {'login':'bar', 'password':'password'}
        auth = 'foo:password'.encode('base64').rstrip()
        creds_auth = 'bar:password'.encode('base64').rstrip()
        environ = self._makeEnviron({'HTTP_COOKIE':'oatmeal=%s;' % auth})
        result = plugin.post_extract(environ, creds, plugin)
        expected = 'oatmeal=%s; Path=/;' % creds_auth
        self.assertEqual(result, [('Set-Cookie', expected)])
        self.assertEqual(environ['HTTP_COOKIE'], 'oatmeal=%s;' % creds_auth)

    def test_factory(self):
        from repoze.pam.plugins.cookie import make_plugin
        plugin = make_plugin(None, 'foo')
        self.assertEqual(plugin.cookie_name, 'foo')


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
    def challenge(self, environ, status, headers):
        environ['challenged'] = True

class DummyPostExtractor:
    def post_extract(self, environ, credentials, extractor):
        return [ ('foo', 'bar') ]
    
