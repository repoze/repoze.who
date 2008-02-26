import os
import unittest

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
                 identifiers=None,
                 authenticators=None,
                 challengers=None,
                 classifier=None,
                 challenge_decider=None,
                 log_stream=None,
                 log_level=None,
                 ):
        if app is None:
            app = DummyApp()
        if identifiers is None:
            identifiers = []
        if authenticators is None:
            authenticators = []
        if challengers is None:
            challengers = []
        if classifier is None:
            classifier = DummyRequestClassifier()
        if challenge_decider is None:
            challenge_decider = DummyChallengeDecider()
        if log_level is None:
            import logging
            log_level = logging.DEBUG
        mw = self._getTargetClass()(app,
                                    identifiers,
                                    authenticators,
                                    challengers,
                                    classifier,
                                    challenge_decider,
                                    log_stream,
                                    log_level=logging.DEBUG)
        return mw

    def test_identify_success(self):
        environ = self._makeEnviron()
        identifier = DummyIdentifier()
        identifiers = [ ('i', identifier) ]
        mw = self._makeOne(identifiers=identifiers)
        results = mw.identify(environ, None)
        self.assertEqual(len(results), 1)
        new_identifier, identity = results[0]
        self.assertEqual(new_identifier, identifier)
        self.assertEqual(identity['login'], 'chris')
        self.assertEqual(identity['password'], 'password')

    def test_identify_fail(self):
        environ = self._makeEnviron()
        plugin = DummyNoResultsIdentifier()
        plugins = [ ('dummy', plugin) ]
        mw = self._makeOne(identifiers=plugins)
        results = mw.identify(environ, None)
        self.assertEqual(len(results), 0)

    def test_identify_success_skip_noresults(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        plugin1 = DummyNoResultsIdentifier()
        plugin2 = DummyIdentifier() 
        plugins = [ ('identifier1', plugin1), ('identifier2', plugin2) ]
        mw = self._makeOne(identifiers=plugins)
        results = mw.identify(environ, None)
        self.assertEqual(len(results), 1)
        new_identifier, identity = results[0]
        self.assertEqual(new_identifier, plugin2)
        self.assertEqual(identity['login'], 'chris')
        self.assertEqual(identity['password'], 'password')

    def test_identify_success_multiresults(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        plugin1 = DummyIdentifier({'login':'fred','password':'fred'})
        plugin2 = DummyIdentifier({'login':'bob','password':'bob'})
        plugins = [ ('identifier1', plugin1), ('identifier2', plugin2) ]
        mw = self._makeOne(identifiers=plugins)
        results = mw.identify(environ, None)
        self.assertEqual(len(results), 2)
        new_identifier, identity = results[0]
        self.assertEqual(new_identifier, plugin1)
        self.assertEqual(identity['login'], 'fred')
        self.assertEqual(identity['password'], 'fred')
        new_identifier, identity = results[1]
        self.assertEqual(new_identifier, plugin2)
        self.assertEqual(identity['login'], 'bob')
        self.assertEqual(identity['password'], 'bob')

    def test_identify_find_implicit_classifier(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        plugin1 = DummyIdentifier({'login':'fred','password':'fred'})
        plugin1.classifications = set(['nomatch'])
        plugin2 = DummyIdentifier({'login':'bob','password':'bob'})
        plugins = [ ('identifier1', plugin1),  ('identifier2', plugin2) ]
        mw = self._makeOne(identifiers=plugins)
        results = mw.identify(environ, 'match')
        self.assertEqual(len(results), 1)
        plugin, creds = results[0]
        self.assertEqual(creds['login'], 'bob')
        self.assertEqual(creds['password'], 'bob')
        self.assertEqual(plugin, plugin2)

    def test_identify_find_explicit_classifier(self):
        environ = self._makeEnviron()
        plugin1 = DummyIdentifier({'login':'fred','password':'fred'})
        plugin1.classifications = set(['nomatch'])
        plugin2 = DummyIdentifier({'login':'bob','password':'bob'})
        plugin2.classifications = set(['match'])
        plugins= [ ('identifier1', plugin1), ('identifier2', plugin2) ]
        mw = self._makeOne(identifiers=plugins)
        results = mw.identify(environ, 'match')
        self.assertEqual(len(results), 1)
        plugin, creds = results[0]
        self.assertEqual(creds['login'], 'bob')
        self.assertEqual(creds['password'], 'bob')
        self.assertEqual(plugin, plugin2)

    def test_authenticate_success(self):
        environ = self._makeEnviron()
        plugin1 = DummyAuthenticator('a')
        plugins = [ ('identifier1', plugin1) ]
        mw = self._makeOne(authenticators=plugins)
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = mw.authenticate(environ, None, identities)
        self.assertEqual(len(results), 1)
        result = results[0]
        authinfo, identinfo, creds, userid = result
        self.assertEqual(authinfo, (0, plugin1))
        self.assertEqual(identinfo, (0, None))
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'a')

    def test_authenticate_fail(self):
        environ = self._makeEnviron()
        mw = self._makeOne() # no authenticators
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        result = mw.authenticate(environ, None, identities)
        self.assertEqual(len(result), 0)

    def test_authenticate_success_skip_fail(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        plugin1 = DummyFailAuthenticator()
        plugin2 = DummyAuthenticator()
        plugins = [ ('dummy1', plugin1), ('dummy2', plugin2) ]
        mw = self._makeOne(authenticators=plugins)
        creds = {'login':'chris', 'password':'password'}
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = mw.authenticate(environ, None, identities)
        self.assertEqual(len(results), 1)
        result = results[0]
        authinfo, identinfo, creds, userid = result
        self.assertEqual(authinfo, (1, plugin2))
        self.assertEqual(identinfo, (0, None))
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris')

    def test_authenticate_success_multiresult(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        plugin1 = DummyAuthenticator('chris_id1')
        plugin2 = DummyAuthenticator('chris_id2')
        plugins = [ ('dummy1',plugin1), ('dummy2',plugin2) ]
        mw = self._makeOne(authenticators=plugins)
        creds = {'login':'chris', 'password':'password'}
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = mw.authenticate(environ, None, identities)
        self.assertEqual(len(results), 2)
        result = results[0]
        authinfo, identinfo, creds, userid = result
        self.assertEqual(authinfo, (0, plugin1))
        self.assertEqual(identinfo, (0, None))
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id1')
        result = results[1]
        authinfo, identinfo, creds, userid = result
        self.assertEqual(authinfo, (1, plugin2))
        self.assertEqual(identinfo, (0, None))
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id2')

    def test_authenticate_find_implicit_classifier(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        plugin1 = DummyAuthenticator('chris_id1')
        plugin1.classifications = set(['nomatch'])
        plugin2 = DummyAuthenticator('chris_id2')
        plugins = [ ('auth1', plugin1), ('auth2', plugin2) ]
        mw = self._makeOne(authenticators = plugins)
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = mw.authenticate(environ, 'match', identities)
        self.assertEqual(len(results), 1)
        result = results[0]
        authinfo, identinfo, creds, userid = result
        self.assertEqual(authinfo, (0, plugin2))
        self.assertEqual(identinfo, (0, None))
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id2')

    def test_authenticate_find_explicit_classifier(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        plugin1 = DummyAuthenticator('chris_id1')
        plugin1.classifications = set(['nomatch'])
        plugin2 = DummyAuthenticator('chris_id2')
        plugin2.classificationans = set(['match']) # game
        plugins = [ ('auth1', plugin1), ('auth2', plugin2) ]
        mw = self._makeOne(authenticators = plugins)
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = mw.authenticate(environ, 'match', identities)
        self.assertEqual(len(results), 1)
        result = results[0]
        authinfo, identinfo, creds, userid = result
        self.assertEqual(authinfo, (0, plugin2))
        self.assertEqual(identinfo, (0, None))
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id2')

    def test_challenge_noidentifier_noapp(self):
        environ = self._makeEnviron()
        challenger = DummyChallenger()
        challenger.classifications = None
        plugins = [ ('challenge', challenger) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        app = mw.challenge(environ, 'match', '401 Unauthorized',
                               [], None, identity)
        self.assertEqual(app, None)
        self.assertEqual(environ['challenged'], app)

    def test_challenge_noidentifier_withapp(self):
        environ = self._makeEnviron()
        app = DummyApp()
        challenger = DummyChallenger(app)
        challenger.classifications = None
        plugins = [ ('challenge', challenger) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = mw.challenge(environ, 'match', '401 Unauthorized',
                               [], None, identity)
        self.assertEqual(result, app)
        self.assertEqual(environ['challenged'], app)

    def test_challenge_identifier_noapp(self):
        environ = self._makeEnviron()
        challenger = DummyChallenger()
        challenger.classifications = None
        identifier = DummyIdentifier()
        plugins = [ ('challenge', challenger) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = mw.challenge(environ, 'match', '401 Unauthorized',
                              [], identifier, identity)
        self.assertEqual(result, None)
        self.assertEqual(environ['challenged'], None)
        self.assertEqual(identifier.forgotten, True)

    def test_challenge_identifier_app(self):
        environ = self._makeEnviron()
        app = DummyApp()
        challenger = DummyChallenger(app)
        challenger.classifications = None
        identifier = DummyIdentifier()
        plugins = [ ('challenge', challenger) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = mw.challenge(environ, 'match', '401 Unauthorized',
                               [], identifier, identity)
        self.assertEqual(result, app)
        self.assertEqual(environ['challenged'], app)
        self.assertEqual(identifier.forgotten, True)

    def test_multi_challenge_firstwins(self):
        environ = self._makeEnviron()
        app1 = DummyApp()
        app2 = DummyApp()
        challenger1 = DummyChallenger(app1)
        challenger1.classifications = None
        challenger2 = DummyChallenger(app2)
        challenger2.classifications = None
        identifier = DummyIdentifier()
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = mw.challenge(environ, 'match', '401 Unauthorized',
                              [], identifier, identity)
        self.assertEqual(result, app1)
        self.assertEqual(environ['challenged'], app1)
        self.assertEqual(identifier.forgotten, True)

    def test_multi_challenge_skipnomatch_findimplicit(self):
        environ = self._makeEnviron()
        app1 = DummyApp()
        app2 = DummyApp()
        challenger1 = DummyChallenger(app1)
        challenger1.classifications = ['nomatch']
        challenger2 = DummyChallenger(app2)
        challenger2.classifications = None
        identifier = DummyIdentifier()
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = mw.challenge(environ, 'match', '401 Unauthorized',
                               [], identifier, identity)
        self.assertEqual(result, app2)
        self.assertEqual(environ['challenged'], app2)
        self.assertEqual(identifier.forgotten, True)

    def test_multi_challenge_skipnomatch_findexplicit(self):
        environ = self._makeEnviron()
        app1 = DummyApp()
        app2 = DummyApp()
        challenger1 = DummyChallenger(app1)
        challenger1.classifications = ['nomatch']
        challenger2 = DummyChallenger(app2)
        challenger2.classifications = ['match']
        identifier = DummyIdentifier()
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = mw.challenge(environ, 'match', '401 Unauthorized',
                               [], identifier, identity)
        self.assertEqual(result, app2)
        self.assertEqual(environ['challenged'], app2)
        self.assertEqual(identifier.forgotten, True)

    def test_call_remoteuser_already_set(self):
        environ = self._makeEnviron({'REMOTE_USER':'admin'})
        mw = self._makeOne()
        result = mw(environ, None)
        self.assertEqual(mw.app.environ, environ)
        self.assertEqual(result, [])

    # XXX need more call tests

class TestStartResponseWrapper(unittest.TestCase):
    def _getTargetClass(self):
        from repoze.pam.middleware import StartResponseWrapper
        return StartResponseWrapper

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def test_ctor(self):
        wrapper = self._makeOne(None)
        self.assertEqual(wrapper.start_response, None)
        self.assertEqual(wrapper.headers, [])
        self.failUnless(wrapper.buffer)
    
    def test_finish_response(self):
        statuses = []
        headerses = []
        datases = []
        closededs = []
        from StringIO import StringIO
        def write(data):
            datases.append(data)
        def close():
            closededs.append(True)
        write.close = close
            
        def start_response(status, headers):
            statuses.append(status)
            headerses.append(headers)
            return write
            
        wrapper = self._makeOne(start_response)
        wrapper.status = '401 Unauthorized'
        wrapper.headers = [('a', '1')]
        wrapper.buffer = StringIO('written')
        extra_headers = [('b', '2')]
        result = wrapper.finish_response(extra_headers)
        self.assertEqual(result, None)
        self.assertEqual(headerses[0], wrapper.headers + extra_headers)
        self.assertEqual(statuses[0], wrapper.status)
        self.assertEqual(datases[0], 'written')
        self.assertEqual(closededs[0], True)

class TestBasicAuthPlugin(Base):
    def _getTargetClass(self):
        from repoze.pam.plugins.basicauth import BasicAuthPlugin
        return BasicAuthPlugin

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.pam.interfaces import IChallenger
        from repoze.pam.interfaces import IIdentifier
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
        self.assertEqual(creds, {})

    def test_identify_nonbasic(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Digest abc'})
        creds = plugin.identify(environ)
        self.assertEqual(creds, {})

    def test_identify_basic_badencoding(self):
        plugin = self._makeOne('realm')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic abc'})
        creds = plugin.identify(environ)
        self.assertEqual(creds, {})

    def test_identify_basic_badrepr(self):
        plugin = self._makeOne('realm')
        value = 'foo'.encode('base64')
        environ = self._makeEnviron({'HTTP_AUTHORIZATION':'Basic %s' % value})
        creds = plugin.identify(environ)
        self.assertEqual(creds, {})

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
        from repoze.pam.interfaces import IAuthenticator
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
        from repoze.pam.interfaces import IIdentifier
        klass = self._getTargetClass()
        verifyClass(IIdentifier, klass)

    def test_identify_nocookies(self):
        plugin = self._makeOne('oatmeal')
        environ = self._makeEnviron()
        result = plugin.identify(environ)
        self.assertEqual(result, {})
        
    def test_identify_badcookies(self):
        plugin = self._makeOne('oatmeal')
        environ = self._makeEnviron({'HTTP_COOKIE':'oatmeal=a'})
        result = plugin.identify(environ)
        self.assertEqual(result, {})

    def test_identify_badcookies(self):
        plugin = self._makeOne('oatmeal')
        environ = self._makeEnviron({'HTTP_COOKIE':'oatmeal=a'})
        result = plugin.identify(environ)
        self.assertEqual(result, {})
    
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
        from repoze.pam.plugins.cookie import make_plugin
        plugin = make_plugin(None, 'foo')
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
        from repoze.pam.plugins.form import FormPlugin
        return FormPlugin

    def _makeOne(self, login_form_qs='__do_login', rememberer_name='cookie'):
        plugin = self._getTargetClass()(login_form_qs, rememberer_name)
        return plugin

    def _makeFormEnviron(self, login=None, password=None, do_login=False):
        from StringIO import StringIO
        fields = []
        if login:
            fields.append(('login', login))
        if password:
            fields.append(('password', password))
        content_type, body = encode_multipart_formdata(fields)
        extra = {'wsgi.input':StringIO(body),
                 'CONTENT_TYPE':content_type,
                 'CONTENT_LENGTH':len(body),
                 'REQUEST_METHOD':'POST',
                 'repoze.pam.plugins': {'cookie':DummyIdentifier()},
                 'QUERY_STRING':'',
                 }
        if do_login:
            extra['QUERY_STRING'] = '__do_login=true'
        environ = self._makeEnviron(extra)
        return environ
    
    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.pam.interfaces import IIdentifier
        from repoze.pam.interfaces import IChallenger
        klass = self._getTargetClass()
        verifyClass(IIdentifier, klass)
        verifyClass(IChallenger, klass)

    def test_identify_noqs(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        result = plugin.identify(environ)
        self.assertEqual(result, {})
        
    def test_identify_qs_no_values(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(do_login=True)
        result = plugin.identify(environ)
        self.assertEqual(result, {})

    def test_identify_nologin(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(do_login=True, login='chris')
        result = plugin.identify(environ)
        self.assertEqual(result, {})
    
    def test_identify_nopassword(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(do_login=True, password='password')
        result = plugin.identify(environ)
        self.assertEqual(result, {})

    def test_identify_success(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron(do_login=True, login='chris',
                                        password='password')
        result = plugin.identify(environ)
        self.assertEqual(result, {'login':'chris', 'password':'password'})

    def test_remember(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        result = plugin.remember(environ, {})
        self.assertEqual(result, None)
        self.assertEqual(environ['repoze.pam.plugins']['cookie'].remembered,
                         True)

    def test_forget(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        result = plugin.forget(environ, {})
        self.assertEqual(result, None)
        self.assertEqual(environ['repoze.pam.plugins']['cookie'].forgotten,
                         True)

    def test_factory(self):
        from repoze.pam.plugins.cookie import make_plugin
        plugin = make_plugin(None, 'foo')
        self.assertEqual(plugin.cookie_name, 'foo')


class TestDefaultRequestClassifier(Base):
    def _getFUT(self):
        from repoze.pam.classifiers import default_request_classifier
        return default_request_classifier

    def test_classify_dav_method(self):
        classifier = self._getFUT()
        environ = self._makeEnviron({'REQUEST_METHOD':'COPY'})
        result = classifier(environ)
        self.assertEqual(result, 'dav')

    def test_classify_dav_useragent(self):
        classifier = self._getFUT()
        environ = self._makeEnviron({'HTTP_USER_AGENT':'WebDrive'})
        result = classifier(environ)
        self.assertEqual(result, 'dav')
        
    def test_classify_xmlpost(self):
        classifier = self._getFUT()
        environ = self._makeEnviron({'CONTENT_TYPE':'text/xml',
                                     'REQUEST_METHOD':'POST'})
        result = classifier(environ)
        self.assertEqual(result, 'xmlpost')

    def test_classify_browser(self):
        classifier = self._getFUT()
        environ = self._makeEnviron({'CONTENT_TYPE':'text/xml',
                                     'REQUEST_METHOD':'GET'})
        result = classifier(environ)
        self.assertEqual(result, 'browser')

class TestMakeRegistries(unittest.TestCase):
    def _getFUT(self):
        from repoze.pam.middleware import make_registries
        return make_registries

    def test_empty(self):
        fn = self._getFUT()
        iface_reg, name_reg = fn([], [], [])
        self.assertEqual(iface_reg, {})
        self.assertEqual(name_reg, {})
        
    def test_brokenimpl(self):
        fn = self._getFUT()
        self.assertRaises(ValueError, fn, [(None, DummyApp())], [], [])

    def test_ok(self):
        fn = self._getFUT()
        dummy_id1 = DummyIdentifier()
        dummy_id2 = DummyIdentifier()
        identifiers = [ ('id1', dummy_id1), ('id2', dummy_id2) ]
        dummy_auth = DummyAuthenticator(None)
        authenticators = [ ('auth', dummy_auth) ]
        dummy_challenger = DummyChallenger(None)
        challengers = [ ('challenger', dummy_challenger) ]
        iface_reg, name_reg = fn(identifiers, authenticators, challengers)
        from repoze.pam.interfaces import IIdentifier
        from repoze.pam.interfaces import IAuthenticator
        from repoze.pam.interfaces import IChallenger
        self.assertEqual(iface_reg[IIdentifier], [dummy_id1, dummy_id2])
        self.assertEqual(iface_reg[IAuthenticator], [dummy_auth])
        self.assertEqual(iface_reg[IChallenger], [dummy_challenger])
        self.assertEqual(name_reg['id1'], dummy_id1)
        self.assertEqual(name_reg['id2'], dummy_id2)
        self.assertEqual(name_reg['auth'], dummy_auth)
        self.assertEqual(name_reg['challenger'], dummy_challenger)

# XXX need make_middleware tests

class DummyApp:
    def __call__(self, environ, start_response):
        self.environ = environ
        return []
    
class DummyRequestClassifier:
    def __call__(self, environ):
        return 'browser'

class DummyIdentifier:
    forgotten = False
    remembered = False
    def __init__(self, credentials=None):
        if credentials is None:
            credentials = {'login':'chris', 'password':'password'}
        self.credentials = credentials

    def identify(self, environ):
        return self.credentials

    def forget(self, environ, identity):
        self.forgotten = True

    def remember(self, environ, identity):
        self.remembered = True

class DummyNoResultsIdentifier:
    def identify(self, environ):
        return {}

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

class DummyFailAuthenticator:
    def authenticate(self, environ, credentials):
        return None

class DummyChallenger:
    def __init__(self, app=None):
        self.app = app
    def challenge(self, environ, status, app_headers, forget_headers):
        environ['challenged'] = self.app
        return self.app

class DummyChallengeDecider:
    def __call__(self, environ, status, headers):
        if status.startswith('401 '):
            return True
        
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
