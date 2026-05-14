import io
import logging
import unittest
from unittest import mock
from wsgiref import util as wsgiref_util

from webob import exc as webob_exc
from repoze.who import middleware



def _make_pam(
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
        log_level = logging.DEBUG

    return middleware.PluggableAuthenticationMiddleware(
        app,
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


def _make_wsgi_environ():
    environ = {}
    wsgiref_util.setup_testing_defaults(environ)
    return environ


def _check_result_prefix(result, exp_prefix):
    to_string = b''.join(result).decode('ascii')
    assert to_string.startswith(exp_prefix)


class TestMiddleware(unittest.TestCase):

    def test_pam_ctor_positional_args(self):
        app = DummyApp()
        identifiers = []
        authenticators = []
        challengers = []
        request_classifier = DummyRequestClassifier()
        mdproviders = []
        challenge_decider = DummyChallengeDecider()

        mw = middleware.PluggableAuthenticationMiddleware(
            app,
            identifiers,
            authenticators,
            challengers,
            mdproviders,
            request_classifier,
            challenge_decider,
        )

        self.assertIs(mw.app, app)

        af = mw.api_factory
        self.assertEqual(af.identifiers, identifiers)
        self.assertEqual(af.authenticators, authenticators)
        self.assertEqual(af.challengers, challengers)
        self.assertEqual(af.mdproviders, mdproviders)
        self.assertEqual(af.request_classifier, request_classifier)
        self.assertEqual(af.challenge_decider, challenge_decider)

    def test_pam_ctor_wo_request_classifier_or_classifier_raises(self):
        # BBB for old argument name
        app = DummyApp()
        identifiers = []
        authenticators = []
        challengers = []
        mdproviders = []
        challenge_decider = DummyChallengeDecider()
        self.assertRaises(ValueError,
                          middleware.PluggableAuthenticationMiddleware,
                          app,
                          identifiers,
                          authenticators,
                          challengers,
                          mdproviders,
                          challenge_decider = challenge_decider,
                          )

    def test_pam_ctor_w_request_classifier_and_classifier_raises(self):
        # BBB for old argument name
        app = DummyApp()
        identifiers = []
        authenticators = []
        challengers = []
        request_classifier = DummyRequestClassifier()
        mdproviders = []
        challenge_decider = DummyChallengeDecider()
        self.assertRaises(ValueError,
                          middleware.PluggableAuthenticationMiddleware,
                          app,
                          identifiers,
                          authenticators,
                          challengers,
                          mdproviders,
                          request_classifier,
                          challenge_decider,
                          classifier = object()
                          )

    def test_pam_ctor_wo_challenge_decider_raises(self):
        # BBB for old argument name
        app = DummyApp()
        identifiers = []
        authenticators = []
        challengers = []
        request_classifier = DummyRequestClassifier()
        mdproviders = []
        self.assertRaises(ValueError,
                          middleware.PluggableAuthenticationMiddleware,
                          app,
                          identifiers,
                          authenticators,
                          challengers,
                          mdproviders,
                          classifier = request_classifier,
                          )

    def test_pam_ctor_w_classifier(self):
        # BBB for old argument name
        app = DummyApp()
        identifiers = []
        authenticators = []
        challengers = []
        request_classifier = DummyRequestClassifier()
        mdproviders = []
        challenge_decider = DummyChallengeDecider()

        mw = middleware.PluggableAuthenticationMiddleware(
            app,
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

    def test_pam_ctor_accepts_logger(self):
        restore = logging.raiseExceptions
        logging.raiseExceptions = 0
        try:
            logger = logging.Logger('something')
            logger.setLevel(logging.INFO)
            mw = _make_pam(log_stream=logger)
            self.assertEqual(logger, mw.logger)
        finally:
            logging.raiseExceptions = restore

    def test_pam_call_remoteuser_already_set(self):
        environ = _make_wsgi_environ() | {'REMOTE_USER':'admin'}
        mw = _make_pam()

        result = mw(environ, None)

        self.assertEqual(result, [])

        self.assertEqual(mw.app.environ, environ)

    def test_pam_call_200_no_plugins(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        mw = _make_pam(app=app)
        start_response = DummyStartResponse()

        result = mw(environ, start_response)

        self.assertEqual(result, ['body'])

        self.assertEqual(mw.app.environ, environ)
        self.assertEqual(start_response.status, '200 OK')
        self.assertEqual(start_response.headers, headers)

    def test_pam_call_401_no_challengers(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        app = DummyWorkingApp('401 Unauthorized', headers)
        mw = _make_pam(app=app)
        start_response = DummyStartResponse()

        self.assertRaises(RuntimeError, mw, environ, start_response)

    def test_pam_call_200_no_challengers(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        mw = _make_pam(app=app, identifiers=identifiers)
        start_response = DummyStartResponse()

        result = mw(environ, start_response)

        self.assertEqual(result, ['body'])

        self.assertEqual(mw.app.environ, environ)
        self.assertEqual(start_response.status, '200 OK')
        self.assertEqual(start_response.headers, headers)

    def test_pam_call_200_no_challengers_app_calls_forget(self):
        # See https://github.com/repoze/repoze.who/issues/21
        environ = _make_wsgi_environ()
        remember_headers = [('remember', '1')]
        forget_headers = [('forget', '1')]
        app = DummyLogoutApp('200 OK')
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(
            credentials,
            remember_headers=remember_headers,
            forget_headers=forget_headers)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mw = _make_pam(
            app=app, identifiers=identifiers, authenticators=authenticators)
        start_response = DummyStartResponse()

        result = mw(environ, start_response)

        self.assertEqual(result, ['body'])

        self.assertEqual(mw.app.environ, environ)
        self.assertEqual(start_response.status, '200 OK')
        self.assertEqual(start_response.headers, forget_headers)

    def test_pam_call_401_no_identifiers(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        app = DummyWorkingApp('401 Unauthorized', headers)
        challenge_app = webob_exc.HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        mw = _make_pam(app=app, challengers=challengers)
        start_response = DummyStartResponse()

        result = mw(environ, start_response)

        _check_result_prefix(result, '401 Unauthorized')

        self.assertEqual(environ['challenged'], challenge_app)

    def test_pam_call_401_challenger_and_identifier_no_authenticator(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        app = DummyWorkingApp('401 Unauthorized', headers)
        challenge_app = webob_exc.HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'a', 'password':'b'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        mw = _make_pam(app=app, challengers=challengers,
                           identifiers=identifiers)
        start_response = DummyStartResponse()

        result = mw(environ, start_response)

        _check_result_prefix(result, '401 Unauthorized')

        self.assertEqual(environ['challenged'], challenge_app)
        self.assertEqual(identifier.forgotten, False)
        self.assertEqual(environ.get('REMOTE_USER'), None)

    def test_pam_call_401_challenger_and_identifier_and_authenticator(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        app = DummyWorkingApp('401 Unauthorized', headers)
        challenge_app = webob_exc.HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mw = _make_pam(app=app, challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators)
        start_response = DummyStartResponse()

        result = mw(environ, start_response)

        _check_result_prefix(result, '401 Unauthorized')

        self.assertEqual(environ['challenged'], challenge_app)
        # @@ unfuck
##         self.assertEqual(identifier.forgotten, identifier.credentials)
        self.assertEqual(environ['REMOTE_USER'], 'chris')
##         self.assertEqual(environ['repoze.who.identity'], identifier.credentials)

    def test_pam_call_200_challenger_and_identifier_and_authenticator(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        challenge_app = webob_exc.HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mw = _make_pam(app=app, challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators)
        start_response = DummyStartResponse()

        _result = mw(environ, start_response)

        self.assertEqual(environ.get('challenged'), None)
        self.assertEqual(identifier.forgotten, False)
        # @@ figure out later
##         self.assertEqual(dict(identifier.remembered)['login'], dict(identifier.credentials)['login'])
##         self.assertEqual(dict(identifier.remembered)['password'], dict(identifier.credentials)['password'])
        self.assertEqual(environ['REMOTE_USER'], 'chris')
##         self.assertEqual(environ['repoze.who.identity'], identifier.credentials)


    def test_pam_call_200_identity_reset(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        new_identity = {'user_id':'foo', 'password':'bar'}
        app = DummyIdentityResetApp('200 OK', headers, new_identity)
        challenge_app = webob_exc.HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mw = _make_pam(app=app, challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators)
        start_response = DummyStartResponse()

        _result = mw(environ, start_response)

        self.assertEqual(environ.get('challenged'), None)
        self.assertEqual(identifier.forgotten, False)
        new_credentials = identifier.credentials.copy()
        new_credentials['login'] = 'fred'
        new_credentials['password'] = 'schooled'
        # @@ unfuck
##         self.assertEqual(identifier.remembered, new_credentials)
        self.assertEqual(environ['REMOTE_USER'], 'chris')
##         self.assertEqual(environ['repoze.who.identity'], new_credentials)

    def test_pam_call_200_with_metadata(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        challenge_app = webob_exc.HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mdprovider = DummyMDProvider({'foo':'bar'})
        mdproviders = [ ('mdprovider', mdprovider) ]
        mw = _make_pam(app=app, challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators,
                           mdproviders=mdproviders)
        start_response = DummyStartResponse()

        _result = mw(environ, start_response)

        # metadata
        self.assertEqual(environ['repoze.who.identity']['foo'], 'bar')

    def test_pam_call_ingress_plugin_replaces_application(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        challengers = []
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(
            credentials,
            remember_headers=[('a', '1')],
            replace_app = webob_exc.HTTPFound('http://example.com/redirect')
            )
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mdproviders = []
        mw = _make_pam(app=app,
                           challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators,
                           mdproviders=mdproviders)
        start_response = DummyStartResponse()

        result = mw(environ, start_response)

        _check_result_prefix(result, '302 Found')

        self.assertEqual(start_response.status, '302 Found')
        headers = start_response.headers
        #self.assertEqual(len(headers), 3, headers)
        #self.assertEqual(headers[0],
        #                 ('Location', 'http://example.com/redirect'))
        self.assertEqual(headers[2],
                         ('Content-Type', 'text/plain; charset=UTF-8'))
        self.assertEqual(headers[3],
                         ('a', '1'))
        self.assertEqual(start_response.exc_info, None)
        self.assertFalse('repoze.who.application' in environ)

    def test_pam_call_app_doesnt_call_start_response(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        app = DummyGeneratorApp('200 OK', headers)
        challenge_app = webob_exc.HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mdprovider = DummyMDProvider({'foo':'bar'})
        mdproviders = [ ('mdprovider', mdprovider) ]
        mw = _make_pam(app=app, challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators,
                           mdproviders=mdproviders)
        start_response = DummyStartResponse()

        _result = mw(environ, start_response)
        # metadata
        self.assertEqual(environ['repoze.who.identity']['foo'], 'bar')

    def test_pam_call_w_challenge_closes_iterable(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        app = DummyIterableWithCloseApp('401 Unauthorized', headers)
        challenge_app = webob_exc.HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mdprovider = DummyMDProvider({'foo':'bar'})
        mdproviders = [ ('mdprovider', mdprovider) ]
        mw = _make_pam(app=app, challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators,
                           mdproviders=mdproviders)
        start_response = DummyStartResponse()

        result = mw(environ, start_response)

        _check_result_prefix(result, '401 Unauthorized')

        self.assertTrue(app._iterable._closed)

    def test_pam_call_w_challenge_but_no_challenger_still_closes_iterable(self):
        environ = _make_wsgi_environ()
        headers = [('a', '1')]
        app = DummyIterableWithCloseApp('401 Unauthorized', headers)
        challengers = []
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('identifier', identifier) ]
        authenticator = DummyAuthenticator()
        authenticators = [ ('authenticator', authenticator) ]
        mdprovider = DummyMDProvider({'foo':'bar'})
        mdproviders = [ ('mdprovider', mdprovider) ]
        mw = _make_pam(app=app, challengers=challengers,
                           identifiers=identifiers,
                           authenticators=authenticators,
                           mdproviders=mdproviders)
        start_response = DummyStartResponse()
        self.assertRaises(RuntimeError, mw, environ, start_response)
        self.assertTrue(app._iterable._closed)

    # XXX need more call tests:
    #  - auth_id sorting

class TestStartResponseWrapper(unittest.TestCase):

    def test_srw_ctor(self):
        wrapper = middleware.StartResponseWrapper(None)
        self.assertEqual(wrapper.start_response, None)
        self.assertEqual(wrapper.headers, [])
        self.assertTrue(wrapper.buffer)

    def test_srw_finish_response(self):
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

        wrapper = middleware.StartResponseWrapper(start_response)
        wrapper.status = '401 Unauthorized'
        wrapper.headers = [('a', '1')]
        wrapper.buffer = io.StringIO('written')
        extra_headers = [('b', '2')]

        result = wrapper.finish_response(extra_headers)

        self.assertIs(result, None)
        self.assertEqual(headerses[0], wrapper.headers + extra_headers)
        self.assertEqual(statuses[0], wrapper.status)
        self.assertEqual(datases[0], 'written')
        self.assertEqual(closededs[0], True)

class WrapGeneratorTests(unittest.TestCase):

    def _callFUT(self, iterable):
        return middleware.wrap_generator(iterable)

    def test_wg_w_generator(self):
        L = []
        def gen(L=L):
            L.append('yo!')
            yield 'a'
            yield 'b'
        newgen = self._callFUT(gen())
        self.assertEqual(L, ['yo!'])
        self.assertEqual(list(newgen), ['a', 'b'])

    def test_wg_w_empty_generator(self):
        def gen():
            if False:
                yield 'a'  # pragma: no cover
        newgen = self._callFUT(gen())
        self.assertEqual(list(newgen), [])

    def test_wg_w_iterator_having_close(self):
        def gen():
            yield 'a'
            yield 'b'
        iterable = DummyIterableWithClose(gen())
        newgen = self._callFUT(iterable)
        self.assertFalse(iterable._closed)
        self.assertEqual(list(newgen), ['a', 'b'])
        self.assertTrue(iterable._closed)

class TestMakeTestMiddleware(unittest.TestCase):

    def test_mtm_no_WHO_LOG_in_environ(self):
        app = DummyApp()
        global_conf = {'here': '/'}

        with mock.patch("os.environ", {}):
            mw_inst = middleware.make_test_middleware(app, global_conf)

        api_factory = mw_inst.api_factory

        self.assertEqual(len(api_factory.identifiers), 2)
        self.assertEqual(len(api_factory.authenticators), 1)
        self.assertEqual(len(api_factory.challengers), 2)
        self.assertEqual(len(api_factory.mdproviders), 0)
        self.assertEqual(mw_inst.logger, None)

    def test_mtm_w_WHO_LOG_in_environ(self):
        app = DummyApp()
        global_conf = {'here': '/'}

        with mock.patch("os.environ", {}) as patched_environ:
            patched_environ['WHO_LOG'] = '1'
            mw_inst = middleware.make_test_middleware(app, global_conf)

        self.assertEqual(mw_inst.logger.getEffectiveLevel(), logging.DEBUG)


class DummyApp(object):
    environ = None
    def __call__(self, environ, start_response):
        self.environ = environ
        return []

class DummyWorkingApp(object):
    def __init__(self, status, headers):
        self.status = status
        self.headers = headers

    def __call__(self, environ, start_response):
        self.environ = environ
        start_response(self.status, self.headers)
        return ['body']

class DummyLogoutApp(object):
    def __init__(self, status):
        self.status = status

    def __call__(self, environ, start_response):
        self.environ = environ
        api = environ['repoze.who.api']
        headers = api.logout()
        start_response(self.status, headers)
        return ['body']

class DummyGeneratorApp(object):
    def __init__(self, status, headers):
        self.status = status
        self.headers = headers

    def __call__(self, environ, start_response):
        def gen(self=self, start_response=start_response):
            self.environ = environ
            start_response(self.status, self.headers)
            yield 'body'
        return gen()

class DummyIterableWithClose(object):
    _closed = False
    def __init__(self, iterable):
        self._iterable = iterable
    def __iter__(self):
        return iter(self._iterable)
    def close(self):
        self._closed = True

class DummyIterableWithCloseApp(object):
    def __init__(self, status, headers):
        self.status = status
        self.headers = headers
        self._iterable = DummyIterableWithClose(['body'])

    def __call__(self, environ, start_response):
        self.environ = environ
        start_response(self.status, self.headers)
        return self._iterable

class DummyIdentityResetApp(object):
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

class DummyChallenger(object):
    def __init__(self, app=None):
        self.app = app

    def challenge(self, environ, status, app_headers, forget_headers):
        environ['challenged'] = self.app
        return self.app

class DummyIdentifier(object):
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

class DummyAuthenticator(object):
    def authenticate(self, environ, credentials):
        return credentials['login']

class DummyRequestClassifier(object):
    def __call__(self, environ):
        return 'browser'

class DummyChallengeDecider(object):
    def __call__(self, environ, status, headers):
        if status.startswith('401 '):
            return True

class DummyStartResponse(object):
    def __call__(self, status, headers, exc_info=None):
        self.status = status
        self.headers = headers
        self.exc_info = exc_info
        return []

class DummyMDProvider(object):
    def __init__(self, metadata=None):
        self._metadata = metadata

    def add_metadata(self, environ, identity):
        return identity.update(self._metadata)
