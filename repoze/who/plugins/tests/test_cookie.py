import unittest

class TestInsecureCookiePlugin(unittest.TestCase):

    def _getTargetClass(self):
        from repoze.who.plugins.cookie import InsecureCookiePlugin
        return InsecureCookiePlugin

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
        from repoze.who.interfaces import IIdentifier
        klass = self._getTargetClass()
        verifyClass(IIdentifier, klass)

    def test_identify_nocookies(self):
        plugin = self._makeOne('oatmeal')
        environ = self._makeEnviron()
        result = plugin.identify(environ)
        self.assertEqual(result, None)
        
    def test_identify_badcookies(self):
        plugin = self._makeOne('oatmeal')
        environ = self._makeEnviron({'HTTP_COOKIE':'oatmeal=a'})
        result = plugin.identify(environ)
        self.assertEqual(result, None)
        
    def test_identify_badcookies_binascci_but_not_splittable(self):
        plugin = self._makeOne('oatmeal')
        auth = 'bogus'.encode('base64').rstrip()
        environ = self._makeEnviron({'HTTP_COOKIE':'oatmeal=%s' % auth})
        result = plugin.identify(environ)
        self.assertEqual(result, None)

    def test_identify_success(self):
        plugin = self._makeOne('oatmeal')
        auth = 'foo:password'.encode('base64').rstrip()
        environ = self._makeEnviron({'HTTP_COOKIE':'oatmeal=%s;' % auth})
        result = plugin.identify(environ)
        self.assertEqual(result, {'login':'foo', 'password':'password'})

    def test_identify_encoded(self):
        LOGIN = 'tr\xc3\xa9sbien'       # UTF-8 encoded e-acute
        PASSWORD = 'p\xc3\x80ssword'    # UTF-8 encoded capital A grave
        plugin = self._makeOne('oatmeal', charset='utf-8')
        auth = ('%s:%s' % (LOGIN, PASSWORD)).encode('base64').rstrip()
        environ = self._makeEnviron({'HTTP_COOKIE':'oatmeal=%s;' % auth})
        result = plugin.identify(environ)
        self.assertEqual(result, {'login': LOGIN.decode('utf8'),
                                  'password': PASSWORD.decode('utf8')})

    def test_remember_creds_same(self):
        plugin = self._makeOne('oatmeal')
        creds = {'login':'foo', 'password':'password'}
        auth = 'foo:password'.encode('base64').rstrip()
        auth = 'oatmeal=%s;' % auth
        environ = self._makeEnviron({'HTTP_COOKIE':auth})
        result = plugin.remember(environ, creds)
        self.assertEqual(result, None)

    def test_remember_creds_different(self):
        plugin = self._makeOne('oatmeal')
        creds = {'login':'bar', 'password':'password'}
        auth = 'foo:password'.encode('base64').rstrip()
        creds_auth = 'bar:password'.encode('base64').rstrip()
        environ = self._makeEnviron({'HTTP_COOKIE':'oatmeal=%s;' % auth})
        result = plugin.remember(environ, creds)
        expected = 'oatmeal=%s; Path=/;' % creds_auth
        self.assertEqual(result, [('Set-Cookie', expected)])

    def test_remember_encoded(self):
        LOGIN = 'tr\xc3\xa9sbien'       # UTF-8 encoded e-acute
        PASSWORD = 'p\xc3\x80ssword'    # UTF-8 encoded capital A grave
        plugin = self._makeOne('oatmeal', charset='utf-8')
        creds = {'login': LOGIN.decode('utf8'),
                 'password': PASSWORD.decode('utf8')}
        creds_auth = ('%s:%s' % (LOGIN, PASSWORD)).encode('base64').rstrip()
        environ = self._makeEnviron()
        result = plugin.remember(environ, creds)
        expected = 'oatmeal=%s; Path=/;' % creds_auth
        self.assertEqual(result, [('Set-Cookie', expected)])

    def test_forget(self):
        plugin = self._makeOne('oatmeal')
        headers = plugin.forget({}, None)
        self.assertEqual(len(headers), 1)
        header = headers[0]
        name, value = header
        self.assertEqual(name, 'Set-Cookie')
        self.assertEqual(value,
            'oatmeal=""; Path=/; Expires=Sun, 10-May-1971 11:59:00 GMT')

    def test_factory(self):
        from repoze.who.plugins.cookie import make_plugin
        plugin = make_plugin('foo')
        self.assertEqual(plugin.cookie_name, 'foo')
        self.assertEqual(plugin.charset, None)

    def test_factory_with_cookie_path(self):
        from repoze.who.plugins.cookie import make_plugin
        plugin = make_plugin('foo', '/bar')
        self.assertEqual(plugin.cookie_name, 'foo')
        self.assertEqual(plugin.cookie_path, '/bar')

    def test_factory_with_charset(self):
        from repoze.who.plugins.cookie import make_plugin
        plugin = make_plugin('foo', charset='utf8')
        self.assertEqual(plugin.cookie_name, 'foo')
        self.assertEqual(plugin.charset, 'utf8')
