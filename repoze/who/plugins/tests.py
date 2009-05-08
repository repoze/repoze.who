import os
import unittest

class Base(unittest.TestCase):
    def _makeEnviron(self, kw=None):
        environ = {}
        environ['wsgi.version'] = (1,0)
        if kw is not None:
            environ.update(kw)
        return environ

class TestBasicAuthPlugin(Base):

    def _getTargetClass(self):
        from repoze.who.plugins.basicauth import BasicAuthPlugin
        return BasicAuthPlugin

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IChallenger
        from repoze.who.interfaces import IIdentifier
        klass = self._getTargetClass()
        verifyClass(IChallenger, klass)
        verifyClass(IIdentifier, klass)

    def test_challenge(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron()
        result = plugin.challenge(environ, '401 Unauthorized', [], [])
        self.assertNotEqual(result, None)
        app_iter = result(environ, lambda *arg: None)
        items = []
        for item in app_iter:
            items.append(item)
        response = ''.join(items)
        self.failUnless(response.startswith('401 Unauthorized'))
        
    def test_identify_noauthinfo(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron()
        creds = plugin.identify(environ)
        self.assertEqual(creds, None)

    def test_identify_nonbasic(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Digest abc'})
        creds = plugin.identify(environ)
        self.assertEqual(creds, None)

    def test_identify_basic_badencoding(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic abc'})
        creds = plugin.identify(environ)
        self.assertEqual(creds, None)

    def test_identify_basic_badrepr(self):
        plugin = self._makeOne('realm')
        value = 'foo'.encode('base64')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic %s' % value})
        creds = plugin.identify(environ)
        self.assertEqual(creds, None)

    def test_identify_basic_ok(self):
        plugin = self._makeOne('realm')
        value = 'foo:bar'.encode('base64')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic %s' % value})
        creds = plugin.identify(environ)
        self.assertEqual(creds, {'login':'foo', 'password':'bar'})

    def test_remember(self):
        plugin = self._makeOne('realm')
        creds = {}
        environ = self._makeEnviron()
        result = plugin.remember(environ, creds)
        self.assertEqual(result, None)

    def test_forget(self):
        plugin = self._makeOne('realm')
        creds = {'login':'foo', 'password':'password'}
        environ = self._makeEnviron()
        result = plugin.forget(environ, creds)
        self.assertEqual(result, [('WWW-Authenticate', 'Basic realm="realm"')] )

    def test_challenge_forgetheaders_includes(self):
        plugin = self._makeOne('realm')
        creds = {'login':'foo', 'password':'password'}
        environ = self._makeEnviron()
        forget = plugin._get_wwwauth()
        result = plugin.challenge(environ, '401 Unauthorized', [], forget)
        self.assertEqual(result.headers, forget)
        
    def test_challenge_forgetheaders_omits(self):
        plugin = self._makeOne('realm')
        creds = {'login':'foo', 'password':'password'}
        environ = self._makeEnviron()
        forget = plugin._get_wwwauth()
        result = plugin.challenge(environ, '401 Unauthorized', [], [])
        self.assertEqual(result.headers, forget)


    def test_factory(self):
        from repoze.who.plugins.basicauth import make_plugin
        plugin = make_plugin('realm')
        self.assertEqual(plugin.realm, 'realm')

class TestHTPasswdPlugin(Base):

    def _getTargetClass(self):
        from repoze.who.plugins.htpasswd import HTPasswdPlugin
        return HTPasswdPlugin

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IAuthenticator
        klass = self._getTargetClass()
        verifyClass(IAuthenticator, klass)

    def test_authenticate_nocreds(self):
        from StringIO import StringIO
        io = StringIO()
        plugin = self._makeOne(io, None)
        environ = self._makeEnviron()
        creds = {}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, None)
        
    def test_authenticate_nolines(self):
        from StringIO import StringIO
        io = StringIO()
        plugin = self._makeOne(io, None)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, None)
        
    def test_authenticate_nousermatch(self):
        from StringIO import StringIO
        io = StringIO('nobody:foo')
        plugin = self._makeOne(io, None)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, None)

    def test_authenticate_match(self):
        from StringIO import StringIO
        io = StringIO('chrism:pass')
        def check(password, hashed):
            return True
        plugin = self._makeOne(io, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, 'chrism')

    def test_authenticate_badline(self):
        from StringIO import StringIO
        io = StringIO('badline\nchrism:pass')
        def check(password, hashed):
            return True
        plugin = self._makeOne(io, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, 'chrism')

    def test_authenticate_filename(self):
        here = os.path.abspath(os.path.dirname(__file__))
        htpasswd = os.path.join(here, 'fixtures', 'test.htpasswd')
        def check(password, hashed):
            return True
        plugin = self._makeOne(htpasswd, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, 'chrism')

    def test_authenticate_bad_filename_logs_to_repoze_who_logger(self):
        here = os.path.abspath(os.path.dirname(__file__))
        htpasswd = os.path.join(here, 'fixtures', 'test.htpasswd.nonesuch')
        def check(password, hashed):
            return True
        plugin = self._makeOne(htpasswd, check)
        environ = self._makeEnviron()
        class DummyLogger:
            warnings = []
            def warn(self, msg):
                self.warnings.append(msg)
        logger = environ['repoze.who.logger'] = DummyLogger()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, None)
        self.assertEqual(len(logger.warnings), 1)
        self.failUnless('could not open htpasswd' in logger.warnings[0])

    def test_crypt_check(self):
        import sys
        # win32 does not have a crypt library, don't
        # fail here
        if "win32" == sys.platform:
            return

        from crypt import crypt
        salt = '123'
        hashed = crypt('password', salt)
        from repoze.who.plugins.htpasswd import crypt_check
        self.assertEqual(crypt_check('password', hashed), True)
        self.assertEqual(crypt_check('notpassword', hashed), False)

    def test_factory(self):
        from repoze.who.plugins.htpasswd import make_plugin
        from repoze.who.plugins.htpasswd import crypt_check
        plugin = make_plugin('foo',
                             'repoze.who.plugins.htpasswd:crypt_check')
        self.assertEqual(plugin.filename, 'foo')
        self.assertEqual(plugin.check, crypt_check)


class TestInsecureCookiePlugin(Base):

    def _getTargetClass(self):
        from repoze.who.plugins.cookie import InsecureCookiePlugin
        return InsecureCookiePlugin

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

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

    def test_identify_success(self):
        plugin = self._makeOne('oatmeal')
        auth = 'foo:password'.encode('base64').rstrip()
        environ = self._makeEnviron({'HTTP_COOKIE':'oatmeal=%s;' % auth})
        result = plugin.identify(environ)
        self.assertEqual(result, {'login':'foo', 'password':'password'})

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

    def test_factory(self):
        from repoze.who.plugins.cookie import make_plugin
        plugin = make_plugin('foo')
        self.assertEqual(plugin.cookie_name, 'foo')

    def test_forget(self):
        plugin = self._makeOne('oatmeal')
        headers = plugin.forget({}, None)
        self.assertEqual(len(headers), 1)
        header = headers[0]
        name, value = header
        self.assertEqual(name, 'Set-Cookie')
        self.assertEqual(value,
            'oatmeal=""; Path=/; Expires=Sun, 10-May-1971 11:59:00 GMT')

class TestFormPlugin(Base):

    def _getTargetClass(self):
        from repoze.who.plugins.form import FormPlugin
        return FormPlugin

    def _makeOne(self, login_form_qs='__do_login', rememberer_name='cookie',
                 formbody=None):
        plugin = self._getTargetClass()(login_form_qs, rememberer_name,
                                        formbody)
        return plugin

    def _makeFormEnviron(self, login=None, password=None, do_login=False):
        from StringIO import StringIO
        fields = []
        if login:
            fields.append(('login', login))
        if password:
            fields.append(('password', password))
        content_type, body = encode_multipart_formdata(fields)
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)

        extra = {'wsgi.input':StringIO(body),
                 'wsgi.url_scheme': 'http',
                 'SERVER_NAME': 'localhost',
                 'SERVER_PORT': '8080',
                 'CONTENT_TYPE':content_type,
                 'CONTENT_LENGTH':len(body),
                 'REQUEST_METHOD':'POST',
                 'repoze.who.plugins': {'cookie':identifier},
                 'PATH_INFO': '/protected',
                 'QUERY_STRING':'',
                 }
        if do_login:
            extra['QUERY_STRING'] = '__do_login=true'
        environ = self._makeEnviron(extra)
        return environ
    
    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IIdentifier
        from repoze.who.interfaces import IChallenger
        klass = self._getTargetClass()
        verifyClass(IIdentifier, klass)
        verifyClass(IChallenger, klass)

    def test_identify_noqs(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        result = plugin.identify(environ)
        self.assertEqual(result, None)
        
    def test_identify_qs_no_values(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(do_login=True)
        result = plugin.identify(environ)
        self.assertEqual(result, None)

    def test_identify_nologin(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(do_login=True, login='chris')
        result = plugin.identify(environ)
        self.assertEqual(result, None)
    
    def test_identify_nopassword(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(do_login=True, password='password')
        result = plugin.identify(environ)
        self.assertEqual(result, None)

    def test_identify_success(self):
        from paste.httpexceptions import HTTPFound
        plugin = self._makeOne()
        environ = self._makeFormEnviron(do_login=True, login='chris',
                                        password='password')
        result = plugin.identify(environ)
        self.assertEqual(result, {'login':'chris', 'password':'password'})
        app = environ['repoze.who.application']
        self.failUnless(isinstance(app, HTTPFound))
        self.assertEqual(app.location(), 'http://localhost:8080/protected')

    def test_remember(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        identity = {}
        result = plugin.remember(environ, identity)
        self.assertEqual(result, None)
        self.assertEqual(environ['repoze.who.plugins']['cookie'].remembered,
                         identity)

    def test_forget(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        identity = {}
        result = plugin.forget(environ, identity)
        self.assertEqual(result, None)
        self.assertEqual(environ['repoze.who.plugins']['cookie'].forgotten,
                         identity
                         )

    def test_challenge_defaultform(self):
        from repoze.who.plugins.form import _DEFAULT_FORM
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        app = plugin.challenge(environ, '401 Unauthorized', [], [])
        sr = DummyStartResponse()
        result = app(environ, sr)
        self.assertEqual(''.join(result), _DEFAULT_FORM)
        self.assertEqual(len(sr.headers), 2)
        cl = str(len(_DEFAULT_FORM))
        self.assertEqual(sr.headers[0], ('Content-Length', cl))
        self.assertEqual(sr.headers[1], ('Content-Type', 'text/html'))
        self.assertEqual(sr.status, '200 OK')

    def test_challenge_customform(self):
        here = os.path.dirname(__file__)
        fixtures = os.path.join(here, 'fixtures')
        form = os.path.join(fixtures, 'form.html')
        formbody = open(form).read()
        plugin = self._makeOne(formbody=formbody)
        environ = self._makeFormEnviron()
        app = plugin.challenge(environ, '401 Unauthorized', [], [])
        sr = DummyStartResponse()
        result = app(environ, sr)
        self.assertEqual(''.join(result), formbody)
        self.assertEqual(len(sr.headers), 2)
        cl = str(len(formbody))
        self.assertEqual(sr.headers[0], ('Content-Length', cl))
        self.assertEqual(sr.headers[1], ('Content-Type', 'text/html'))
        self.assertEqual(sr.status, '200 OK')

    def test_challenge_with_location(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        app = plugin.challenge(environ, '401 Unauthorized',
                               [('Location', 'http://foo/bar')],
                               [('Set-Cookie', 'a=123')])
        sr = DummyStartResponse()
        app(environ, sr)
        headers = sorted(sr.headers)
        self.assertEqual(len(headers), 3)
        self.assertEqual(headers[0], ('Location', 'http://foo/bar'))
        self.assertEqual(headers[1],
                         ('Set-Cookie', 'a=123'))
        self.assertEqual(headers[2],
                         ('content-type', 'text/plain; charset=utf8'))
        self.assertEqual(sr.status, '302 Found')

    def test_factory_withform(self):
        from repoze.who.plugins.form import make_plugin
        here = os.path.dirname(__file__)
        fixtures = os.path.join(here, 'fixtures')
        form = os.path.join(fixtures, 'form.html')
        formbody = open(form).read()
        plugin = make_plugin('__login', 'cookie', form)
        self.assertEqual(plugin.login_form_qs, '__login')
        self.assertEqual(plugin.rememberer_name, 'cookie')
        self.assertEqual(plugin.formbody, formbody)

    def test_factory_defaultform(self):
        from repoze.who.plugins.form import make_plugin
        plugin = make_plugin('__login', 'cookie')
        self.assertEqual(plugin.login_form_qs, '__login')
        self.assertEqual(plugin.rememberer_name, 'cookie')
        self.assertEqual(plugin.formbody, None)

class TestRedirectingFormPlugin(Base):

    def _getTargetClass(self):
        from repoze.who.plugins.form import RedirectingFormPlugin
        return RedirectingFormPlugin

    def _makeOne(self, login_form_url='http://example.com/login.html',
                 login_handler_path = '/login_handler',
                 logout_handler_path = '/logout_handler',
                 rememberer_name='cookie',
                 reason_param='reason'):
        plugin = self._getTargetClass()(login_form_url, login_handler_path,
                                        logout_handler_path,
                                        rememberer_name, reason_param)
        return plugin

    def _makeFormEnviron(self, login=None, password=None, came_from=None,
                         path_info='/', identifier=None):
        from StringIO import StringIO
        fields = []
        if login:
            fields.append(('login', login))
        if password:
            fields.append(('password', password))
        if came_from:
            fields.append(('came_from', came_from))
        if identifier is None:
            credentials = {'login':'chris', 'password':'password'}
            identifier = DummyIdentifier(credentials)
        content_type, body = encode_multipart_formdata(fields)
        extra = {'wsgi.input':StringIO(body),
                 'wsgi.url_scheme':'http',
                 'SERVER_NAME':'www.example.com',
                 'SERVER_PORT':'80',
                 'CONTENT_TYPE':content_type,
                 'CONTENT_LENGTH':len(body),
                 'REQUEST_METHOD':'POST',
                 'repoze.who.plugins': {'cookie':identifier},
                 'QUERY_STRING':'default=1',
                 'PATH_INFO':path_info,
                 }
        environ = self._makeEnviron(extra)
        return environ
    
    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IIdentifier
        from repoze.who.interfaces import IChallenger
        klass = self._getTargetClass()
        verifyClass(IIdentifier, klass)
        verifyClass(IChallenger, klass)

    def test_identify_pathinfo_miss(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(path_info='/not_login_handler')
        result = plugin.identify(environ)
        self.assertEqual(result, None)
        self.failIf(environ.get('repoze.who.application'))
        
    def test_identify_via_login_handler(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(path_info='/login_handler',
                                        login='chris',
                                        password='password',
                                        came_from='http://example.com')
        result = plugin.identify(environ)
        self.assertEqual(result, {'login':'chris', 'password':'password'})
        app = environ['repoze.who.application']
        self.assertEqual(len(app.headers), 1)
        name, value = app.headers[0]
        self.assertEqual(name, 'location')
        self.assertEqual(value, 'http://example.com')
        self.assertEqual(app.code, 302)

    def test_identify_via_login_handler_no_username_pass(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(path_info='/login_handler')
        result = plugin.identify(environ)
        self.assertEqual(result, None)
        app = environ['repoze.who.application']
        self.assertEqual(len(app.headers), 1)
        name, value = app.headers[0]
        self.assertEqual(name, 'location')
        self.assertEqual(value, '/')
        self.assertEqual(app.code, 302)

    def test_identify_via_login_handler_no_came_from_no_http_referer(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(path_info='/login_handler',
                                        login='chris',
                                        password='password')
        result = plugin.identify(environ)
        self.assertEqual(result, {'login':'chris', 'password':'password'})
        app = environ['repoze.who.application']
        self.assertEqual(len(app.headers), 1)
        name, value = app.headers[0]
        self.assertEqual(name, 'location')
        self.assertEqual(value, '/')
        self.assertEqual(app.code, 302)

    def test_identify_via_login_handler_no_came_from(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(path_info='/login_handler',
                                        login='chris',
                                        password='password')
        environ['HTTP_REFERER'] = 'http://foo.bar'
        result = plugin.identify(environ)
        self.assertEqual(result, {'login':'chris', 'password':'password'})
        app = environ['repoze.who.application']
        self.assertEqual(len(app.headers), 1)
        name, value = app.headers[0]
        self.assertEqual(name, 'location')
        self.assertEqual(value, 'http://foo.bar')
        self.assertEqual(app.code, 302)

    def test_identify_via_logout_handler(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(path_info='/logout_handler',
                                        login='chris',
                                        password='password',
                                        came_from='http://example.com')
        result = plugin.identify(environ)
        self.assertEqual(result, None)
        app = environ['repoze.who.application']
        self.assertEqual(len(app.headers), 0)
        self.assertEqual(app.code, 401)
        self.assertEqual(environ['came_from'], 'http://example.com')

    def test_identify_via_logout_handler_no_came_from_no_http_referer(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(path_info='/logout_handler',
                                        login='chris',
                                        password='password')
        result = plugin.identify(environ)
        self.assertEqual(result, None)
        app = environ['repoze.who.application']
        self.assertEqual(len(app.headers), 0)
        self.assertEqual(app.code, 401)
        self.assertEqual(environ['came_from'], '/')

    def test_identify_via_logout_handler_no_came_from(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(path_info='/logout_handler',
                                        login='chris',
                                        password='password')
        environ['HTTP_REFERER'] = 'http://example.com/referer'
        result = plugin.identify(environ)
        self.assertEqual(result, None)
        app = environ['repoze.who.application']
        self.assertEqual(len(app.headers), 0)
        self.assertEqual(app.code, 401)
        self.assertEqual(environ['came_from'], 'http://example.com/referer')

    def test_remember(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        identity = {}
        result = plugin.remember(environ, identity)
        self.assertEqual(result, None)
        self.assertEqual(environ['repoze.who.plugins']['cookie'].remembered,
                         identity)

    def test_forget(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        identity = {}
        result = plugin.forget(environ, identity)
        self.assertEqual(result, None)
        self.assertEqual(environ['repoze.who.plugins']['cookie'].forgotten,
                         identity
                         )

    def test_challenge(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        app = plugin.challenge(environ, '401 Unauthorized', [('app', '1')],
                               [('forget', '1')])
        sr = DummyStartResponse()
        result = ''.join(app(environ, sr))
        self.failUnless(result.startswith('302 Found'))
        self.assertEqual(len(sr.headers), 3)
        self.assertEqual(sr.headers[0][0], 'Location')
        url = sr.headers[0][1]
        import urlparse
        import cgi
        parts = urlparse.urlparse(url)
        parts_qsl = cgi.parse_qsl(parts[4])
        self.assertEqual(len(parts_qsl), 1)
        came_from_key, came_from_value = parts_qsl[0]
        self.assertEqual(parts[0], 'http')
        self.assertEqual(parts[1], 'example.com')
        self.assertEqual(parts[2], '/login.html')
        self.assertEqual(parts[3], '')
        self.assertEqual(came_from_key, 'came_from')
        self.assertEqual(came_from_value, 'http://www.example.com/?default=1')
        headers = sr.headers
        self.assertEqual(len(headers), 3)
        self.assertEqual(sr.headers[1][0], 'forget')
        self.assertEqual(sr.headers[1][1], '1')
        self.assertEqual(sr.headers[2][0], 'content-type')
        self.assertEqual(sr.headers[2][1], 'text/plain; charset=utf8')
        self.assertEqual(sr.status, '302 Found')

    def test_challenge_came_from_in_environ(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        environ['came_from'] = 'http://example.com/came_from'
        app = plugin.challenge(environ, '401 Unauthorized', [('app', '1')],
                               [('forget', '1')])
        sr = DummyStartResponse()
        result = ''.join(app(environ, sr))
        self.failUnless(result.startswith('302 Found'))
        self.assertEqual(len(sr.headers), 3)
        self.assertEqual(sr.headers[0][0], 'Location')
        url = sr.headers[0][1]
        import urlparse
        import cgi
        parts = urlparse.urlparse(url)
        parts_qsl = cgi.parse_qsl(parts[4])
        self.assertEqual(len(parts_qsl), 1)
        came_from_key, came_from_value = parts_qsl[0]
        self.assertEqual(parts[0], 'http')
        self.assertEqual(parts[1], 'example.com')
        self.assertEqual(parts[2], '/login.html')
        self.assertEqual(parts[3], '')
        self.assertEqual(came_from_key, 'came_from')
        self.assertEqual(came_from_value, 'http://example.com/came_from')

    def test_challenge_with_reason_header(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        environ['came_from'] = 'http://example.com/came_from'
        app = plugin.challenge(
            environ, '401 Unauthorized',
            [('X-Authorization-Failure-Reason', 'you are ugly')],
            [('forget', '1')])
        sr = DummyStartResponse()
        result = ''.join(app(environ, sr))
        self.failUnless(result.startswith('302 Found'))
        self.assertEqual(len(sr.headers), 3)
        self.assertEqual(sr.headers[0][0], 'Location')
        url = sr.headers[0][1]
        import urlparse
        import cgi
        parts = urlparse.urlparse(url)
        parts_qsl = cgi.parse_qsl(parts[4])
        self.assertEqual(len(parts_qsl), 2)
        parts_qsl.sort()
        came_from_key, came_from_value = parts_qsl[0]
        reason_key, reason_value = parts_qsl[1]
        self.assertEqual(parts[0], 'http')
        self.assertEqual(parts[1], 'example.com')
        self.assertEqual(parts[2], '/login.html')
        self.assertEqual(parts[3], '')
        self.assertEqual(came_from_key, 'came_from')
        self.assertEqual(came_from_value, 'http://example.com/came_from')
        self.assertEqual(reason_key, 'reason')
        self.assertEqual(reason_value, 'you are ugly')

    def test_challenge_with_reason_and_custom_reason_param(self):
        plugin = self._makeOne(reason_param='auth_failure')
        environ = self._makeFormEnviron()
        environ['came_from'] = 'http://example.com/came_from'
        app = plugin.challenge(
            environ, '401 Unauthorized',
            [('X-Authorization-Failure-Reason', 'you are ugly')],
            [('forget', '1')])
        sr = DummyStartResponse()
        result = ''.join(app(environ, sr))
        self.failUnless(result.startswith('302 Found'))
        self.assertEqual(len(sr.headers), 3)
        self.assertEqual(sr.headers[0][0], 'Location')
        url = sr.headers[0][1]
        import urlparse
        import cgi
        parts = urlparse.urlparse(url)
        parts_qsl = cgi.parse_qsl(parts[4])
        self.assertEqual(len(parts_qsl), 2)
        parts_qsl.sort()
        reason_key, reason_value = parts_qsl[0]
        came_from_key, came_from_value = parts_qsl[1]
        self.assertEqual(parts[0], 'http')
        self.assertEqual(parts[1], 'example.com')
        self.assertEqual(parts[2], '/login.html')
        self.assertEqual(parts[3], '')
        self.assertEqual(came_from_key, 'came_from')
        self.assertEqual(came_from_value, 'http://example.com/came_from')
        self.assertEqual(reason_key, 'auth_failure')
        self.assertEqual(reason_value, 'you are ugly')

    def test_challenge_with_setcookie_from_app(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        app = plugin.challenge(
            environ,
            '401 Unauthorized',
            [('app', '1'), ('set-cookie','a'), ('set-cookie','b')],
            [])
        sr = DummyStartResponse()
        result = ''.join(app(environ, sr))
        self.failUnless(result.startswith('302 Found'))
        self.assertEqual(sr.headers[1][0], 'set-cookie')
        self.assertEqual(sr.headers[1][1], 'a')
        self.assertEqual(sr.headers[2][0], 'set-cookie')
        self.assertEqual(sr.headers[2][1], 'b')

class TestAuthTktCookiePlugin(Base):

    def _getTargetClass(self):
        from repoze.who.plugins.auth_tkt import AuthTktCookiePlugin
        return AuthTktCookiePlugin

    def _makeEnviron(self, *arg, **kw):
        environ = Base._makeEnviron(self, *arg, **kw)
        environ['REMOTE_ADDR'] = '1.1.1.1'
        environ['SERVER_NAME'] = 'localhost'
        return environ

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def _makeTicket(self, userid='userid', remote_addr='0.0.0.0',
                    tokens = [], userdata='userdata',
                    cookie_name='auth_tkt', secure=False):
        from paste.auth import auth_tkt
        ticket = auth_tkt.AuthTicket(
            'secret',
            userid,
            remote_addr,
            tokens=tokens,
            user_data=userdata,
            cookie_name=cookie_name,
            secure=secure)
        return ticket.cookie_value()

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IIdentifier
        klass = self._getTargetClass()
        verifyClass(IIdentifier, klass)

    def test_identify_nocookie(self):
        plugin = self._makeOne('secret')
        environ = self._makeEnviron()
        result = plugin.identify(environ)
        self.assertEqual(result, None)
        
    def test_identify_good_cookie_include_ip(self):
        plugin = self._makeOne('secret', include_ip=True)
        val = self._makeTicket(remote_addr='1.1.1.1')
        environ = self._makeEnviron({'HTTP_COOKIE':'auth_tkt=%s' % val})
        result = plugin.identify(environ)
        self.assertEqual(len(result), 4)
        self.assertEqual(result['tokens'], [''])
        self.assertEqual(result['repoze.who.userid'], 'userid')
        self.assertEqual(result['userdata'], 'userdata')
        self.failUnless('timestamp' in result)
        self.assertEqual(environ['REMOTE_USER_TOKENS'], [''])
        self.assertEqual(environ['REMOTE_USER_DATA'],'userdata')
        self.assertEqual(environ['AUTH_TYPE'],'cookie')

    def test_identify_good_cookie_dont_include_ip(self):
        plugin = self._makeOne('secret', include_ip=False)
        val = self._makeTicket()
        environ = self._makeEnviron({'HTTP_COOKIE':'auth_tkt=%s' % val})
        result = plugin.identify(environ)
        self.assertEqual(len(result), 4)
        self.assertEqual(result['tokens'], [''])
        self.assertEqual(result['repoze.who.userid'], 'userid')
        self.assertEqual(result['userdata'], 'userdata')
        self.failUnless('timestamp' in result)
        self.assertEqual(environ['REMOTE_USER_TOKENS'], [''])
        self.assertEqual(environ['REMOTE_USER_DATA'],'userdata')
        self.assertEqual(environ['AUTH_TYPE'],'cookie')

    def test_identify_good_cookie_int_useridtype(self):
        plugin = self._makeOne('secret', include_ip=False)
        val = self._makeTicket(userid='1', userdata='userid_type:int')
        environ = self._makeEnviron({'HTTP_COOKIE':'auth_tkt=%s' % val})
        result = plugin.identify(environ)
        self.assertEqual(len(result), 4)
        self.assertEqual(result['tokens'], [''])
        self.assertEqual(result['repoze.who.userid'], 1)
        self.assertEqual(result['userdata'], 'userid_type:int')
        self.failUnless('timestamp' in result)
        self.assertEqual(environ['REMOTE_USER_TOKENS'], [''])
        self.assertEqual(environ['REMOTE_USER_DATA'],'userid_type:int')
        self.assertEqual(environ['AUTH_TYPE'],'cookie')

    def test_identify_good_cookie_unknown_useridtype(self):
        plugin = self._makeOne('secret', include_ip=False)
        val = self._makeTicket(userid='userid', userdata='userid_type:unknown')
        environ = self._makeEnviron({'HTTP_COOKIE':'auth_tkt=%s' % val})
        result = plugin.identify(environ)
        self.assertEqual(len(result), 4)
        self.assertEqual(result['tokens'], [''])
        self.assertEqual(result['repoze.who.userid'], 'userid')
        self.assertEqual(result['userdata'], 'userid_type:unknown')
        self.failUnless('timestamp' in result)
        self.assertEqual(environ['REMOTE_USER_TOKENS'], [''])
        self.assertEqual(environ['REMOTE_USER_DATA'],'userid_type:unknown')
        self.assertEqual(environ['AUTH_TYPE'],'cookie')

    def test_identify_bad_cookie(self):
        plugin = self._makeOne('secret', include_ip=True)
        environ = self._makeEnviron({'HTTP_COOKIE':'auth_tkt=bogus'})
        result = plugin.identify(environ)
        self.assertEqual(result, None)
    
    def test_remember_creds_same(self):
        plugin = self._makeOne('secret')
        val = self._makeTicket(userid='userid')
        environ = self._makeEnviron({'HTTP_COOKIE':'auth_tkt=%s' % val})
        result = plugin.remember(environ, {'repoze.who.userid':'userid',
                                           'userdata':'userdata'})
        self.assertEqual(result, None)

    def test_remember_creds_different(self):
        plugin = self._makeOne('secret')
        old_val = self._makeTicket(userid='userid')
        environ = self._makeEnviron({'HTTP_COOKIE':'auth_tkt=%s' % old_val})
        new_val = self._makeTicket(userid='other', userdata='userdata')
        result = plugin.remember(environ, {'repoze.who.userid':'other',
                                           'userdata':'userdata'})
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0],
                         ('Set-Cookie',
                          'auth_tkt="%s"; Path=/' % new_val))
        self.assertEqual(result[1],
                         ('Set-Cookie',
                           'auth_tkt="%s"; Path=/; Domain=localhost' % new_val))
        self.assertEqual(result[2],
                         ('Set-Cookie',
                           'auth_tkt="%s"; Path=/; Domain=.localhost' % new_val))

    def test_remember_creds_different_int_userid(self):
        plugin = self._makeOne('secret')
        old_val = self._makeTicket(userid='userid')
        environ = self._makeEnviron({'HTTP_COOKIE':'auth_tkt=%s' % old_val})
        new_val = self._makeTicket(userid='1', userdata='userid_type:int')
        result = plugin.remember(environ, {'repoze.who.userid':1,
                                           'userdata':''})
        
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0],
                         ('Set-Cookie',
                          'auth_tkt="%s"; Path=/' % new_val))

    def test_remember_creds_different_long_userid(self):
        plugin = self._makeOne('secret')
        old_val = self._makeTicket(userid='userid')
        environ = self._makeEnviron({'HTTP_COOKIE':'auth_tkt=%s' % old_val})
        new_val = self._makeTicket(userid='1', userdata='userid_type:int')
        result = plugin.remember(environ, {'repoze.who.userid':long(1),
                                           'userdata':''})
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0],
                         ('Set-Cookie',
                          'auth_tkt="%s"; Path=/' % new_val))

    def test_remember_creds_different_unicode_userid(self):
        plugin = self._makeOne('secret')
        old_val = self._makeTicket(userid='userid')
        environ = self._makeEnviron({'HTTP_COOKIE':'auth_tkt=%s' % old_val})
        userid = unicode('\xc2\xa9', 'utf-8')
        new_val = self._makeTicket(userid=userid.encode('utf-8'),
                                   userdata='userid_type:unicode')
        result = plugin.remember(environ, {'repoze.who.userid':userid,
                                           'userdata':''})
        self.assertEqual(type(result[0][1]), str)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0],
                         ('Set-Cookie',
                          'auth_tkt="%s"; Path=/' % new_val))

    def test_forget(self):
        plugin = self._makeOne('secret')
        environ = self._makeEnviron()
        headers = plugin.forget(environ, None)
        self.assertEqual(len(headers), 3)
        header = headers[0]
        name, value = header
        self.assertEqual(name, 'Set-Cookie')
        self.assertEqual(value, 'auth_tkt=""""; Path=/')
        header = headers[1]
        name, value = header
        self.assertEqual(name, 'Set-Cookie')
        self.assertEqual(value, 'auth_tkt=""""; Path=/; Domain=localhost')
        header = headers[2]
        name, value = header
        self.assertEqual(name, 'Set-Cookie')
        self.assertEqual(value, 'auth_tkt=""""; Path=/; Domain=.localhost')

    def test_factory_wo_secret_wo_secretfile_raises_ValueError(self):
        from repoze.who.plugins.auth_tkt import make_plugin
        self.assertRaises(ValueError, make_plugin)

    def test_factory_w_secret_w_secretfile_raises_ValueError(self):
        from repoze.who.plugins.auth_tkt import make_plugin
        self.assertRaises(ValueError, make_plugin, 'secret', 'secretfile')

    def test_factory_w_bad_secretfile_raises_ValueError(self):
        from repoze.who.plugins.auth_tkt import make_plugin
        self.assertRaises(ValueError, make_plugin, secretfile='nonesuch.txt')

    def test_factory_w_secret(self):
        from repoze.who.plugins.auth_tkt import make_plugin
        plugin = make_plugin('secret')
        self.assertEqual(plugin.cookie_name, 'auth_tkt')
        self.assertEqual(plugin.secret, 'secret')
        self.assertEqual(plugin.include_ip, False)
        self.assertEqual(plugin.secure, False)

    def test_factory_w_secretfile(self):
        from tempfile import NamedTemporaryFile
        from repoze.who.plugins.auth_tkt import make_plugin
        ntf = NamedTemporaryFile()
        ntf.write('s33kr1t\n')
        ntf.flush()
        plugin = make_plugin(secretfile=ntf.name)
        self.assertEqual(plugin.secret, 's33kr1t')

class TestSQLAuthenticatorPlugin(unittest.TestCase):

    def _makeEnviron(self, kw=None):
        environ = {}
        environ['wsgi.version'] = (1,0)
        if kw is not None:
            environ.update(kw)
        return environ

    def _getTargetClass(self):
        from repoze.who.plugins.sql import SQLAuthenticatorPlugin
        return SQLAuthenticatorPlugin

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IAuthenticator
        klass = self._getTargetClass()
        verifyClass(IAuthenticator, klass, tentative=True)

    def test_authenticate_noresults(self):
        dummy_factory = DummyConnectionFactory([])
        plugin = self._makeOne('select foo from bar', dummy_factory,
                               compare_succeed)
        environ = self._makeEnviron()
        identity = {'login':'foo', 'password':'bar'}
        result = plugin.authenticate(environ, identity)
        self.assertEqual(result, None)
        self.assertEqual(dummy_factory.query, 'select foo from bar')
        self.assertEqual(dummy_factory.closed, True)

    def test_authenticate_comparefail(self):
        dummy_factory = DummyConnectionFactory([ ['userid', 'password'] ])
        plugin = self._makeOne('select foo from bar', dummy_factory,
                               compare_fail)
        environ = self._makeEnviron()
        identity = {'login':'fred', 'password':'bar'}
        result = plugin.authenticate(environ, identity)
        self.assertEqual(result, None)
        self.assertEqual(dummy_factory.query, 'select foo from bar')
        self.assertEqual(dummy_factory.closed, True)

    def test_authenticate_comparesuccess(self):
        dummy_factory = DummyConnectionFactory([ ['userid', 'password'] ])
        plugin = self._makeOne('select foo from bar', dummy_factory,
                               compare_succeed)
        environ = self._makeEnviron()
        identity = {'login':'fred', 'password':'bar'}
        result = plugin.authenticate(environ, identity)
        self.assertEqual(result, 'userid')
        self.assertEqual(dummy_factory.query, 'select foo from bar')
        self.assertEqual(dummy_factory.closed, True)

    def test_authenticate_nologin(self):
        dummy_factory = DummyConnectionFactory([ ['userid', 'password'] ])
        plugin = self._makeOne('select foo from bar', dummy_factory,
                               compare_succeed)
        environ = self._makeEnviron()
        identity = {}
        result = plugin.authenticate(environ, identity)
        self.assertEqual(result, None)
        self.assertEqual(dummy_factory.query, None)
        self.assertEqual(dummy_factory.closed, False)

class TestDefaultPasswordCompare(unittest.TestCase):

    def _getFUT(self):
        from repoze.who.plugins.sql import default_password_compare
        return default_password_compare

    def _get_sha_hex_digest(self, clear='password'):
        try:
            from hashlib import sha1
        except ImportError:
            from sha import new as sha1
        return sha1(clear).hexdigest()

    def test_shaprefix_success(self):
        stored = '{SHA}' +  self._get_sha_hex_digest()
        compare = self._getFUT()
        result = compare('password', stored)
        self.assertEqual(result, True)

    def test_shaprefix_fail(self):
        stored = '{SHA}' + self._get_sha_hex_digest()
        compare = self._getFUT()
        result = compare('notpassword', stored)
        self.assertEqual(result, False)

    def test_noprefix_success(self):
        stored = 'password'
        compare = self._getFUT()
        result = compare('password', stored)
        self.assertEqual(result, True)

    def test_noprefix_fail(self):
        stored = 'password'
        compare = self._getFUT()
        result = compare('notpassword', stored)
        self.assertEqual(result, False)

class TestSQLMetadataProviderPlugin(unittest.TestCase):

    def _getTargetClass(self):
        from repoze.who.plugins.sql import SQLMetadataProviderPlugin
        return SQLMetadataProviderPlugin

    def _makeOne(self, *arg, **kw):
        klass = self._getTargetClass()
        return klass(*arg, **kw)

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IMetadataProvider
        klass = self._getTargetClass()
        verifyClass(IMetadataProvider, klass, tentative=True)

    def test_add_metadata(self):
        dummy_factory = DummyConnectionFactory([ [1, 2, 3] ])
        def dummy_filter(results):
            return results
        plugin = self._makeOne('md', 'select foo from bar', dummy_factory,
                               dummy_filter)
        environ = {}
        identity = {'repoze.who.userid':1}
        plugin.add_metadata(environ, identity)
        self.assertEqual(dummy_factory.closed, True)
        self.assertEqual(identity['md'], [ [1,2,3] ])
        self.assertEqual(dummy_factory.query, 'select foo from bar')
        self.failIf(identity.has_key('__userid'))

class TestMakeSQLAuthenticatorPlugin(unittest.TestCase):

    def _getFUT(self):
        from repoze.who.plugins.sql import make_authenticator_plugin
        return make_authenticator_plugin

    def test_noquery(self):
        f = self._getFUT()
        self.assertRaises(ValueError, f, None, 'conn', 'compare')

    def test_no_connfactory(self):
        f = self._getFUT()
        self.assertRaises(ValueError, f, 'statement', None, 'compare')

    def test_bad_connfactory(self):
        f = self._getFUT()
        self.assertRaises(ValueError, f, 'statement', 'does.not:exist', None)

    def test_connfactory_specd(self):
        f = self._getFUT()
        plugin = f('statement',
                   'repoze.who.plugins.tests:make_dummy_connfactory',
                   None)
        self.assertEqual(plugin.query, 'statement')
        self.assertEqual(plugin.conn_factory, DummyConnFactory)
        from repoze.who.plugins.sql import default_password_compare
        self.assertEqual(plugin.compare_fn, default_password_compare)

    def test_comparefunc_specd(self):
        f = self._getFUT()
        plugin = f('statement',
                   'repoze.who.plugins.tests:make_dummy_connfactory',
                   'repoze.who.plugins.tests:make_dummy_connfactory')
        self.assertEqual(plugin.query, 'statement')
        self.assertEqual(plugin.conn_factory, DummyConnFactory)
        self.assertEqual(plugin.compare_fn, make_dummy_connfactory)

class TestMakeSQLMetadataProviderPlugin(unittest.TestCase):

    def _getFUT(self):
        from repoze.who.plugins.sql import make_metadata_plugin
        return make_metadata_plugin

    def test_no_name(self):
        f = self._getFUT()
        self.assertRaises(ValueError, f)

    def test_no_query(self):
        f = self._getFUT()
        self.assertRaises(ValueError, f, 'name', None, None)

    def test_bad_connfactory(self):
        f = self._getFUT()
        self.assertRaises(ValueError, f, 'name', 'statement',
                          'does.not:exist', None)

    def test_connfactory_specd(self):
        f = self._getFUT()
        plugin = f('name', 'statement',
                   'repoze.who.plugins.tests:make_dummy_connfactory', None)
        self.assertEqual(plugin.name, 'name')
        self.assertEqual(plugin.query, 'statement')
        self.assertEqual(plugin.conn_factory, DummyConnFactory)
        self.assertEqual(plugin.filter, None)

    def test_comparefn_specd(self):
        f = self._getFUT()
        plugin = f('name', 'statement',
                   'repoze.who.plugins.tests:make_dummy_connfactory',
                   'repoze.who.plugins.tests:make_dummy_connfactory')
        self.assertEqual(plugin.name, 'name')
        self.assertEqual(plugin.query, 'statement')
        self.assertEqual(plugin.conn_factory, DummyConnFactory)
        self.assertEqual(plugin.filter, make_dummy_connfactory)


class DummyApp:
    environ = None
    def __call__(self, environ, start_response):
        self.environ = environ
        return []

class DummyWorkingApp:
    def __init__(self, status, headers):
        self.status = status
        self.headers = headers

    def __call__(self, environ, start_response):
        self.environ = environ
        start_response(self.status, self.headers)
        return ['body']

class DummyIdentityResetApp:
    def __init__(self, status, headers, new_identity):
        self.status = status
        self.headers = headers
        self.new_identity = new_identity

    def __call__(self, environ, start_response):
        self.environ = environ
        environ['repoze.who.identity']['login'] = 'fred'
        environ['repoze.who.identity']['password'] = 'schooled'
        start_response(self.status, self.headers)
        return ['body']
    
class DummyRequestClassifier:
    def __call__(self, environ):
        return 'browser'

class DummyIdentifier:
    forgotten = False
    remembered = False

    def __init__(self, credentials=None, remember_headers=None,
                 forget_headers=None, replace_app=None):
        self.credentials = credentials
        self.remember_headers = remember_headers
        self.forget_headers = forget_headers
        self.replace_app = replace_app

    def identify(self, environ):
        if self.replace_app:
            environ['repoze.who.application'] = self.replace_app
        return self.credentials

    def forget(self, environ, identity):
        self.forgotten = identity
        return self.forget_headers

    def remember(self, environ, identity):
        self.remembered = identity
        return self.remember_headers

class DummyNoResultsIdentifier:
    def identify(self, environ):
        return None

    def remember(self, *arg, **kw):
        pass

    def forget(self, *arg, **kw):
        pass

class DummyAuthenticator:
    def __init__(self, userid=None):
        self.userid = userid
        
    def authenticate(self, environ, credentials):
        if self.userid is None:
            return credentials['login']
        return self.userid

class DummyMultiPlugin:
    pass

class DummyFailAuthenticator:
    def authenticate(self, environ, credentials):
        return None

class DummyChallenger:
    def __init__(self, app=None):
        self.app = app

    def challenge(self, environ, status, app_headers, forget_headers):
        environ['challenged'] = self.app
        return self.app

class DummyMDProvider:
    def __init__(self, metadata=None):
        self._metadata = metadata
        
    def add_metadata(self, environ, identity):
        return identity.update(self._metadata)

class DummyChallengeDecider:
    def __call__(self, environ, status, headers):
        if status.startswith('401 '):
            return True

class DummyStartResponse:
    def __call__(self, status, headers, exc_info=None):
        self.status = status
        self.headers = headers
        self.exc_info = exc_info
        return []

class DummyConnectionFactory:
    # acts as all of: a factory, a connection, and a cursor
    closed = False
    query = None
    def __init__(self, results):
        self.results = results

    def __call__(self):
        return self

    def cursor(self):
        return self

    def execute(self, query, *arg):
        self.query = query
        self.bindargs = arg

    def fetchall(self):
        return self.results

    def fetchone(self):
        if self.results:
            return self.results[0]
        return []

    def close(self):
        self.closed = True

def compare_fail(cleartext, stored):
    return False

def compare_succeed(cleartext, stored):
    return True

class _DummyConnFactory:
    pass

DummyConnFactory = _DummyConnFactory()

def make_dummy_connfactory(**kw):
    return DummyConnFactory

def encode_multipart_formdata(fields):
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body
