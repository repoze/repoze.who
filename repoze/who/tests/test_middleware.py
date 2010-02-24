import unittest

class TestMiddleware(unittest.TestCase):

    def _getTargetClass(self):
        from repoze.who.middleware import PluggableAuthenticationMiddleware
        return PluggableAuthenticationMiddleware

    def _makeOne(self,
                 app=None,
                 identifiers=None,
                 authenticators=None,
                 challengers=None,
                 request_classifier=None,
                 mdproviders=None,
                 challenge_decider=None,
                 log_stream=None,
                 log_level=None,
                 remote_user_key='REMOTE_USER',
                 ):
        if app is None:
            app = DummyApp()
        if identifiers is None:
            identifiers = []
        if authenticators is None:
            authenticators = []
        if challengers is None:
            challengers = []
        if request_classifier is None:
            request_classifier = DummyRequestClassifier()
        if mdproviders is None:
            mdproviders = []
        if challenge_decider is None:
            challenge_decider = DummyChallengeDecider()
        if log_level is None:
            import logging
            log_level = logging.DEBUG
        mw = self._getTargetClass()(app,
                                    identifiers,
                                    authenticators,
                                    challengers,
                                    mdproviders,
                                    request_classifier,
                                    challenge_decider,
                                    log_stream,
                                    log_level=logging.DEBUG,
                                    remote_user_key=remote_user_key,
                                   )
        return mw

    def _makeEnviron(self, kw=None):
        environ = {}
        environ['wsgi.version'] = (1,0)
        if kw is not None:
            environ.update(kw)
        return environ

    def test_ctor_positional_args(self):
        klass = self._getTargetClass()
        app = DummyApp()
        identifiers = []
        authenticators = []
        challengers = []
        request_classifier = DummyRequestClassifier()
        mdproviders = []
        challenge_decider = DummyChallengeDecider()
        mw = klass(app,
                   identifiers,
                   authenticators,
                   challengers,
                   mdproviders,
                   request_classifier,
                   challenge_decider,
                  )
        self.assertEqual(mw.app, app)
        af = mw.api_factory
        self.assertEqual(af.identifiers, identifiers)
        self.assertEqual(af.authenticators, authenticators)
        self.assertEqual(af.challengers, challengers)
        self.assertEqual(af.mdproviders, mdproviders)
        self.assertEqual(af.request_classifier, request_classifier)
        self.assertEqual(af.challenge_decider, challenge_decider)

    def test_ctor_wo_request_classifier_or_classifier_raises(self):
        # BBB for old argument name
        klass = self._getTargetClass()
        app = DummyApp()
        identifiers = []
        authenticators = []
        challengers = []
        mdproviders = []
        challenge_decider = DummyChallengeDecider()
        self.assertRaises(ValueError,
                          klass,
                          app,
                          identifiers,
                          authenticators,
                          challengers,
                          mdproviders,
                          challenge_decider = challenge_decider,
                          )

    def test_ctor_w_request_classifier_and_classifier_raises(self):
        # BBB for old argument name
        klass = self._getTargetClass()
        app = DummyApp()
        identifiers = []
        authenticators = []
        challengers = []
        request_classifier = DummyRequestClassifier()
        mdproviders = []
        challenge_decider = DummyChallengeDecider()
        self.assertRaises(ValueError,
                          klass,
                          app,
                          identifiers,
                          authenticators,
                          challengers,
                          mdproviders,
                          request_classifier,
                          challenge_decider,
                          classifier = object()
                          )

    def test_ctor_wo_challenge_decider_raises(self):
        # BBB for old argument name
        klass = self._getTargetClass()
        app = DummyApp()
        identifiers = []
        authenticators = []
        challengers = []
        request_classifier = DummyRequestClassifier()
        mdproviders = []
        self.assertRaises(ValueError,
                          klass,
                          app,
                          identifiers,
                          authenticators,
                          challengers,
                          mdproviders,
                          classifier = request_classifier,
                          )

    def test_ctor_w_classifier(self):
        # BBB for old argument name
        klass = self._getTargetClass()
        app = DummyApp()
        identifiers = []
        authenticators = []
        challengers = []
        request_classifier = DummyRequestClassifier()
        mdproviders = []
        challenge_decider = DummyChallengeDecider()
        mw = klass(app,
                   identifiers,
                   authenticators,
                   challengers,
                   mdproviders,
                   classifier = request_classifier,
                   challenge_decider = challenge_decider,
                  )
        self.assertEqual(mw.app, app)
        af = mw.api_factory
        self.assertEqual(af.identifiers, identifiers)
        self.assertEqual(af.authenticators, authenticators)
        self.assertEqual(af.challengers, challengers)
        self.assertEqual(af.mdproviders, mdproviders)
        self.assertEqual(af.request_classifier, request_classifier)
        self.assertEqual(af.challenge_decider, challenge_decider)

    def test_ctor_accepts_logger(self):
        import logging
        restore = logging.raiseExceptions
        logging.raiseExceptions = 0
        try:
            logger = logging.Logger('something')
            logger.setLevel(logging.INFO)
            mw = self._makeOne(log_stream=logger)
            self.assertEqual(logger, mw.logger)
        finally:
            logging.raiseExceptions = restore

    def test_call_remoteuser_already_set(self):
        environ = self._makeEnviron({'REMOTE_USER':'admin'})
        mw = self._makeOne()
        result = mw(environ, None)
        self.assertEqual(mw.app.environ, environ)
        self.assertEqual(result, [])

    def test_call_200_no_plugins(self):
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        mw = self._makeOne(app=app)
        start_response = DummyStartResponse()
        result = mw(environ, start_response)
        self.assertEqual(mw.app.environ, environ)
        self.assertEqual(result, ['body'])
        self.assertEqual(start_response.status, '200 OK')
        self.assertEqual(start_response.headers, headers)

    def test_call_401_no_challengers(self):
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('401 Unauthorized', headers)
        mw = self._makeOne(app=app)
        start_response = DummyStartResponse()
        self.assertRaises(RuntimeError, mw, environ, start_response)

    def test_call_200_no_challengers(self):
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        mw = self._makeOne(app=app, identifiers=identifiers)
        start_response = DummyStartResponse()
        result = mw(environ, start_response)
        self.assertEqual(mw.app.environ, environ)
        self.assertEqual(result, ['body'])
        self.assertEqual(start_response.status, '200 OK')
        self.assertEqual(start_response.headers, headers)

    def test_call_401_no_identifiers(self):
        from paste.httpexceptions import HTTPUnauthorized
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('401 Unauthorized', headers)
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        mw = self._makeOne(app=app, challengers=challengers)
        start_response = DummyStartResponse()
        result = mw(environ, start_response)
        self.assertEqual(environ['challenged'], challenge_app)
        self.failUnless(result[0].startswith('401 Unauthorized\r\n'))

    def test_call_401_challenger_and_identifier_no_authenticator(self):
        from paste.httpexceptions import HTTPUnauthorized
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('401 Unauthorized', headers)
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'a', 'password':'b'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        mw = self._makeOne(app=app, challengers=challengers,
                           identifiers=identifiers)
        start_response = DummyStartResponse()

        result = mw(environ, start_response)
        self.assertEqual(environ['challenged'], challenge_app)
        self.failUnless(result[0].startswith('401 Unauthorized\r\n'))
        self.assertEqual(identifier.forgotten, False)
        self.assertEqual(environ.get('REMOTE_USER'), None)

    def test_call_401_challenger_and_identifier_and_authenticator(self):
        from paste.httpexceptions import HTTPUnauthorized
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('401 Unauthorized', headers)
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mw = self._makeOne(app=app, challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators)
        start_response = DummyStartResponse()
        result = mw(environ, start_response)
        self.assertEqual(environ['challenged'], challenge_app)
        self.failUnless(result[0].startswith('401 Unauthorized\r\n'))
        # @@ unfuck
##         self.assertEqual(identifier.forgotten, identifier.credentials)
        self.assertEqual(environ['REMOTE_USER'], 'chris')
##         self.assertEqual(environ['repoze.who.identity'], identifier.credentials)

    def test_call_200_challenger_and_identifier_and_authenticator(self):
        from paste.httpexceptions import HTTPUnauthorized
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mw = self._makeOne(app=app, challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators)
        start_response = DummyStartResponse()
        result = mw(environ, start_response)
        self.assertEqual(environ.get('challenged'), None)
        self.assertEqual(identifier.forgotten, False)
        # @@ figure out later
##         self.assertEqual(dict(identifier.remembered)['login'], dict(identifier.credentials)['login'])
##         self.assertEqual(dict(identifier.remembered)['password'], dict(identifier.credentials)['password'])
        self.assertEqual(environ['REMOTE_USER'], 'chris')
##         self.assertEqual(environ['repoze.who.identity'], identifier.credentials)


    def test_call_200_identity_reset(self):
        from paste.httpexceptions import HTTPUnauthorized
        environ = self._makeEnviron()
        headers = [('a', '1')]
        new_identity = {'user_id':'foo', 'password':'bar'}
        app = DummyIdentityResetApp('200 OK', headers, new_identity)
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mw = self._makeOne(app=app, challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators)
        start_response = DummyStartResponse()
        result = mw(environ, start_response)
        self.assertEqual(environ.get('challenged'), None)
        self.assertEqual(identifier.forgotten, False)
        new_credentials = identifier.credentials.copy()
        new_credentials['login'] = 'fred'
        new_credentials['password'] = 'schooled'
        # @@ unfuck
##         self.assertEqual(identifier.remembered, new_credentials)
        self.assertEqual(environ['REMOTE_USER'], 'chris')
##         self.assertEqual(environ['repoze.who.identity'], new_credentials)

    def test_call_200_with_metadata(self):
        from paste.httpexceptions import HTTPUnauthorized
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mdprovider = DummyMDProvider({'foo':'bar'})
        mdproviders = [ ('mdprovider', mdprovider) ]
        mw = self._makeOne(app=app, challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators,
                           mdproviders=mdproviders)
        start_response = DummyStartResponse()
        result = mw(environ, start_response)
        # metadata
        self.assertEqual(environ['repoze.who.identity']['foo'], 'bar')

    def test_call_ingress_plugin_replaces_application(self):
        from paste.httpexceptions import HTTPFound
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        challengers = []
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(
            credentials,
            remember_headers=[('a', '1')],
            replace_app = HTTPFound('http://example.com/redirect')
            )
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mdproviders = []
        mw = self._makeOne(app=app,
                           challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators,
                           mdproviders=mdproviders)
        start_response = DummyStartResponse()
        result = ''.join(mw(environ, start_response))
        self.failUnless(result.startswith('302 Found'))
        self.assertEqual(start_response.status, '302 Found')
        headers = start_response.headers
        self.assertEqual(len(headers), 3, headers)
        self.assertEqual(headers[0],
                         ('location', 'http://example.com/redirect'))
        self.assertEqual(headers[1],
                         ('content-type', 'text/plain; charset=utf8'))
        self.assertEqual(headers[2],
                         ('a', '1'))
        self.assertEqual(start_response.exc_info, None)
        self.failIf(environ.has_key('repoze.who.application'))

    def test_call_app_doesnt_call_start_response(self):
        from paste.httpexceptions import HTTPUnauthorized
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyGeneratorApp('200 OK', headers)
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mdprovider = DummyMDProvider({'foo':'bar'})
        mdproviders = [ ('mdprovider', mdprovider) ]
        mw = self._makeOne(app=app, challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators,
                           mdproviders=mdproviders)
        start_response = DummyStartResponse()
        result = mw(environ, start_response)
        # metadata
        self.assertEqual(environ['repoze.who.identity']['foo'], 'bar')

    # XXX need more call tests:
    #  - auth_id sorting

class TestStartResponseWrapper(unittest.TestCase):

    def _getTargetClass(self):
        from repoze.who.middleware import StartResponseWrapper
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
        from StringIO import StringIO
        statuses = []
        headerses = []
        datases = []
        closededs = []
        def write(data):
            datases.append(data)
        def close():
            closededs.append(True)
        write.close = close

        def start_response(status, headers, exc_info=None):
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

class WrapGeneratorTests(unittest.TestCase):

    def _getFUT(self):
        from repoze.who.middleware import wrap_generator
        return wrap_generator

    def test_it(self):
        L = []
        def gen(L=L):
            L.append('yo!')
            yield 'a'
            yield 'b'
        wrap_generator = self._getFUT()
        newgen = wrap_generator(gen())
        self.assertEqual(L, ['yo!'])
        self.assertEqual(list(newgen), ['a', 'b'])

class TestMakeTestMiddleware(unittest.TestCase):

    def setUp(self):
        import os
        self._old_WHO_LOG = os.environ.get('WHO_LOG')

    def tearDown(self):
        import os
        if self._old_WHO_LOG is not None:
            os.environ['WHO_LOG'] = self._old_WHO_LOG
        else:
            if 'WHO_LOG' in os.environ:
                del os.environ['WHO_LOG']

    def _getFactory(self):
        from repoze.who.middleware import make_test_middleware
        return make_test_middleware

    def test_it_no_WHO_LOG_in_environ(self):
        from repoze.who.interfaces import IIdentifier
        from repoze.who.interfaces import IAuthenticator
        from repoze.who.interfaces import IChallenger
        app = DummyApp()
        factory = self._getFactory()
        global_conf = {'here': '/'}
        middleware = factory(app, global_conf)
        api_factory = middleware.api_factory
        self.assertEqual(len(api_factory.identifiers), 3)
        self.assertEqual(len(api_factory.authenticators), 1)
        self.assertEqual(len(api_factory.challengers), 2)
        self.assertEqual(len(api_factory.mdproviders), 0)
        self.assertEqual(middleware.logger, None)

    def test_it_w_WHO_LOG_in_environ(self):
        import logging
        import os
        os.environ['WHO_LOG'] = '1'
        app = DummyApp()
        factory = self._getFactory()
        global_conf = {'here': '/'}
        middleware = factory(app, global_conf)
        self.assertEqual(middleware.logger.getEffectiveLevel(), logging.DEBUG)

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

class DummyGeneratorApp:
    def __init__(self, status, headers):
        self.status = status
        self.headers = headers

    def __call__(self, environ, start_response):
        def gen(self=self, start_response=start_response):
            self.environ = environ
            start_response(self.status, self.headers)
            yield 'body'
        return gen()

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

class DummyChallenger:
    def __init__(self, app=None):
        self.app = app

    def challenge(self, environ, status, app_headers, forget_headers):
        environ['challenged'] = self.app
        return self.app

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

class DummyRequestClassifier:
    def __call__(self, environ):
        return 'browser'

class DummyChallengeDecider:
    def __call__(self, environ, status, headers):
        if status.startswith('401 '):
            return True

class DummyNoResultsIdentifier:
    def identify(self, environ):
        return None

    def remember(self, *arg, **kw):
        pass

    def forget(self, *arg, **kw):
        pass

class DummyStartResponse:
    def __call__(self, status, headers, exc_info=None):
        self.status = status
        self.headers = headers
        self.exc_info = exc_info
        return []

class DummyMDProvider:
    def __init__(self, metadata=None):
        self._metadata = metadata

    def add_metadata(self, environ, identity):
        return identity.update(self._metadata)

class DummyMultiPlugin:
    pass
