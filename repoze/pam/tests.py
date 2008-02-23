import unittest

class TestBasicAuthPlugin(unittest.TestCase):
    def _getTargetClass(self):
        from repoze.pam.plugins.basicauth import BasicAuthPlugin
        return BasicAuthPlugin

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def _makeEnviron(self, kw=None):
        environ = {}
        environ['wsgi.version'] = (1,0)
        if kw is not None:
            environ.update(kw)
        return environ
    
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
        
