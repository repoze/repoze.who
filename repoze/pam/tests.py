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
        plugin = self._makeOne('realm', [])
        environ = self._makeEnviron()
        from paste.httpexceptions import HTTPUnauthorized
        self.assertRaises(HTTPUnauthorized, plugin.challenge, environ)
        
    def test_extract_noauthinfo(self):
        plugin = self._makeOne('realm', [])
        environ = self._makeEnviron()
        result = plugin.extract(environ)
        self.assertEqual(result, {})

    def test_extract_nonbasic(self):
        plugin = self._makeOne('realm', [])
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Digest abc'})
        result = plugin.extract(environ)
        self.assertEqual(result, {})

    def test_extract_nonbasic(self):
        plugin = self._makeOne('realm', [])
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Digest abc'})
        result = plugin.extract(environ)
        self.assertEqual(result, {})

    def test_extract_basic_badencoding(self):
        plugin = self._makeOne('realm', [])
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic abc'})
        result = plugin.extract(environ)
        self.assertEqual(result, {})

    def test_extract_basic_badrepr(self):
        plugin = self._makeOne('realm', [])
        value = 'foo'.encode('base64')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic %s' % value})
        result = plugin.extract(environ)
        self.assertEqual(result, {})

    def test_extract_basic_ok(self):
        plugin = self._makeOne('realm', [])
        value = 'foo:bar'.encode('base64')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic %s' % value})
        result = plugin.extract(environ)
        self.assertEqual(result, {'login':'foo', 'password':'bar'})

    def test_factory(self):
        from repoze.pam.plugins.basicauth import make_plugin
        plugin = make_plugin({}, 'realm', ['a', 'b'])
        self.assertEqual(plugin.realm, 'realm')
        self.assertEqual(plugin.requests, ['a', 'b'])
        
class TestHTPasswdAuthenticator(Base):
    def _getTargetClass(self):
        from repoze.pam.plugins.htpasswd import HTPasswdAuthenticator
        return HTPasswdAuthenticator

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
        
