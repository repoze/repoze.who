import unittest
from wsgiref import util as wsgiref_util

from zope.interface import exceptions as iface_exc # Invalid
from zope.interface.verify import verifyClass
from zope.interface.verify import verifyObject

from repoze.who import interfaces # IMetadataProvider
from repoze.who import api as api_module # get_api, APIFactory, API


def _make_wsgi_environ():
    environ = {}
    wsgiref_util.setup_testing_defaults(environ)
    return environ


def test_get_api_w_empty_environ():
    environ = {}

    api = api_module.get_api(environ)

    assert api is None


def test_get_api_w_api_in_environ():
    expected = object()
    environ = {'repoze.who.api': expected}

    api = api_module.get_api(environ)

    assert api is expected


def _make_api_factory(
    plugins=None,
    identifiers=None,
    authenticators=None,
    challengers=None,
    mdproviders=None,
    request_classifier=None,
    challenge_decider=None,
    remote_user_key=None,
    logger=None,
):
    if plugins is None:
        plugins = {}

    if identifiers is None:
        identifiers = ()

    if authenticators is None:
        authenticators = ()

    if challengers is None:
        challengers = ()

    if mdproviders is None:
        mdproviders = ()

    return api_module.APIFactory(
        identifiers,
        authenticators,
        challengers,
        mdproviders,
        request_classifier,
        challenge_decider,
        remote_user_key,
        logger,
    )

class APIFactoryTests(unittest.TestCase):

    def test_api_factory_class_conforms_to_IAPIFactory(self):
        verifyClass(interfaces.IAPIFactory, api_module.APIFactory)

    def test_api_factory_instance_conforms_to_IAPIFactory(self):
        inst = _make_api_factory()

        verifyObject(interfaces.IAPIFactory, inst)

    def test_api_factory_ctor_defaults(self):
        factory = _make_api_factory()

        self.assertEqual(len(factory.identifiers), 0)
        self.assertEqual(len(factory.authenticators), 0)
        self.assertEqual(len(factory.challengers), 0)
        self.assertEqual(len(factory.mdproviders), 0)
        self.assertIsNone(factory.request_classifier)
        self.assertIsNone(factory.challenge_decider)
        self.assertIsNone(factory.logger)

    def test_api_factory___call___empty_environ(self):
        environ = {}
        factory = _make_api_factory()

        api = factory(environ)

        self.assertTrue(isinstance(api, api_module.API))
        self.assertIs(environ['repoze.who.api'], api)

    def test_api_factory___call___w_api_in_environ(self):
        expected = object()
        environ = {'repoze.who.api': expected}
        factory = _make_api_factory()

        api = factory(environ)

        self.assertIs(api, expected)


class TestMakeRegistries(unittest.TestCase):

    def test_make_registries_w_empty(self):
        iface_reg, name_reg = api_module.make_registries([], [], [], [])
        self.assertEqual(iface_reg, {})
        self.assertEqual(name_reg, {})

    def test_make_registries_w_brokenimpl(self):
        # BBB for zope.interface < 5.0.0
        expected_exc = (iface_exc.Invalid, ValueError)

        with self.assertRaises(expected_exc):
            api_module.make_registries([(None, object())], [], [], [])

    def test_make_registries_w_ok(self):
        credentials1 = {'login':'chris', 'password':'password'}
        dummy_id1 = DummyIdentifier(credentials1)
        credentials2 = {'login':'chris', 'password':'password'}
        dummy_id2 = DummyIdentifier(credentials2)
        identifiers = [ ('id1', dummy_id1), ('id2', dummy_id2) ]
        dummy_auth = DummyAuthenticator(None)
        authenticators = [ ('auth', dummy_auth) ]
        dummy_challenger = DummyChallenger(None)
        challengers = [ ('challenger', dummy_challenger) ]
        dummy_mdprovider = DummyMDProvider()
        mdproviders = [ ('mdprovider', dummy_mdprovider) ]

        iface_reg, name_reg = api_module.make_registries(
            identifiers,
            authenticators,
            challengers,
            mdproviders,
        )

        self.assertEqual(iface_reg[interfaces.IIdentifier], [dummy_id1, dummy_id2])
        self.assertEqual(iface_reg[interfaces.IAuthenticator], [dummy_auth])
        self.assertEqual(iface_reg[interfaces.IChallenger], [dummy_challenger])
        self.assertEqual(iface_reg[interfaces.IMetadataProvider], [dummy_mdprovider])
        self.assertEqual(name_reg['id1'], dummy_id1)
        self.assertEqual(name_reg['id2'], dummy_id2)
        self.assertEqual(name_reg['auth'], dummy_auth)
        self.assertEqual(name_reg['challenger'], dummy_challenger)
        self.assertEqual(name_reg['mdprovider'], dummy_mdprovider)


class TestMatchClassification(unittest.TestCase):

    def test_match_classification(self):
        multi1 = DummyMultiPlugin()
        multi2 = DummyMultiPlugin()
        multi1.classifications = {
            interfaces.IIdentifier: ('foo', 'bar'),
            interfaces.IChallenger: ('buz',),
            interfaces.IAuthenticator: None,
        }
        multi2.classifications = {
            interfaces.IIdentifier:('foo', 'baz', 'biz'),
        }
        plugins = (multi1, multi2)
        # specific
        self.assertEqual(api_module.match_classification(interfaces.IIdentifier, plugins, 'foo'), [multi1, multi2])
        self.assertEqual(api_module.match_classification(interfaces.IIdentifier, plugins, 'bar'), [multi1])
        self.assertEqual(api_module.match_classification(interfaces.IIdentifier, plugins, 'biz'), [multi2])
        # any for multi2
        self.assertEqual(api_module.match_classification(interfaces.IChallenger, plugins, 'buz'), [multi1, multi2])
        # any for either
        self.assertEqual(api_module.match_classification(interfaces.IAuthenticator, plugins, 'buz'), [multi1, multi2])


class APITests(unittest.TestCase):

    def _makeOne(self,
                 environ=None,
                 identifiers=None,
                 authenticators=None,
                 challengers=None,
                 request_classifier=None,
                 mdproviders=None,
                 challenge_decider=None,
                 remote_user_key=None,
                 logger=None
                 ):
        if environ is None:
            environ = {}
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
        api = api_module.API(environ,
                                     identifiers,
                                     authenticators,
                                     challengers,
                                     mdproviders,
                                     request_classifier,
                                     challenge_decider,
                                     remote_user_key,
                                     logger,
                                    )
        return api

    def test_api_class_conforms_to_IAPI(self):
        verifyClass(interfaces.IAPI, api_module.API)

    def test_api_ctor_accepts_logger_instance(self):
        logger = DummyLogger()
        api = self._makeOne(logger=logger)

        self.assertIs(api.logger, logger)
        self.assertEqual(len(logger._info), 1)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertEqual(len(logger._debug), 0)

    def test_api_authenticate_no_identities(self):
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        plugin = DummyNoResultsIdentifier()
        plugins = [ ('dummy', plugin) ]
        api = self._makeOne(environ=environ,
                            identifiers=plugins,
                            logger=logger)

        identity = api.authenticate()

        self.assertEqual(identity, None)
        self.assertEqual(len(logger._info), 2)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertEqual(logger._info[1], 'no identities found, '
                                          'not authenticating')

    def test_api_authenticate_w_identities_no_authenticators(self):
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('i', identifier) ]
        api = self._makeOne(environ=environ,
                            identifiers=identifiers, logger=logger)

        identity = api.authenticate()

        self.assertEqual(identity, None)
        self.assertEqual(len(logger._info), 2)
        self.assertEqual(logger._info[0], 'request classification: browser')
        # Hmm, should this message distinguish "none found" from
        # "none authenticated"?
        self.assertEqual(logger._info[1], 'no identities found, '
                                          'not authenticating')

    #def test_authenticate_w_identities_w_authenticators_miss(self):
    def test_api_authenticate_w_identities_w_authenticators_hit(self):
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('i', identifier) ]
        authenticator = DummyAuthenticator('chrisid')
        authenticators = [ ('a', authenticator) ]
        api = self._makeOne(environ=environ,
                            identifiers=identifiers,
                            authenticators=authenticators,
                            logger=logger)

        identity = api.authenticate()

        self.assertEqual(identity['repoze.who.userid'], 'chrisid')
        self.assertTrue(identity['identifier'] is identifier)
        self.assertTrue(identity['authenticator'] is authenticator)

        self.assertEqual(len(logger._info), 1)
        self.assertEqual(logger._info[0], 'request classification: browser')

    def test_api_challenge_noidentifier_noapp(self):
        logger = DummyLogger()
        identity = {'login':'chris', 'password':'password'}
        environ = _make_wsgi_environ()
        environ['repoze.who.identity'] = identity
        challenger = DummyChallenger()
        plugins = [ ('challenge', challenger) ]
        api = self._makeOne(environ=environ,
                            challengers=plugins,
                            request_classifier=lambda environ: 'match',
                            logger=logger,
                           )

        app = api.challenge('401 Unauthorized', [])

        self.assertEqual(app, None)
        self.assertEqual(environ['challenged'], None)
        self.assertEqual(len(logger._info), 2)
        self.assertEqual(logger._info[0], 'request classification: match')
        self.assertEqual(logger._info[1], 'no challenge app returned')
        self.assertEqual(len(logger._debug), 2)
        self.assertTrue(logger._debug[0].startswith(
                                        'challengers registered: ['))
        self.assertTrue(logger._debug[1].startswith(
                                        'challengers matched for '
                                        'classification "match": ['))

    def test_api_challenge_noidentifier_with_app(self):
        logger = DummyLogger()
        identity = {'login':'chris', 'password':'password'}
        environ = _make_wsgi_environ()
        environ['repoze.who.identity'] = identity
        app = DummyApp()
        challenger = DummyChallenger(app)
        plugins = [ ('challenge', challenger) ]
        api = self._makeOne(environ=environ,
                            challengers=plugins,
                            request_classifier=lambda environ: 'match',
                            logger=logger,
                           )

        result = api.challenge('401 Unauthorized', [])

        self.assertEqual(result, app)
        self.assertEqual(environ['challenged'], app)
        self.assertEqual(len(logger._info), 2)
        self.assertEqual(logger._info[0], 'request classification: match')
        self.assertTrue(logger._info[1].startswith('challenger plugin '))
        self.assertTrue(logger._info[1].endswith(
                         '"challenge" returned an app'))
        self.assertEqual(len(logger._debug), 2)
        self.assertTrue(logger._debug[0].startswith(
                                        'challengers registered: ['))
        self.assertTrue(logger._debug[1].startswith(
                                        'challengers matched for '
                                        'classification "match": ['))

    def test_api_challenge_identifier_no_app_no_forget_headers(self):
        logger = DummyLogger()
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identity = {'login':'chris',
                    'password':'password',
                    'identifier': identifier}
        environ = _make_wsgi_environ()
        environ['repoze.who.identity'] = identity
        challenger = DummyChallenger()
        plugins = [ ('challenge', challenger) ]
        api = self._makeOne(environ=environ,
                            challengers=plugins,
                            request_classifier=lambda environ: 'match',
                            logger=logger,
                           )

        result = api.challenge('401 Unauthorized', [])

        self.assertEqual(result, None)
        self.assertEqual(environ['challenged'], None)
        self.assertEqual(identifier.forgotten, identity)
        self.assertEqual(len(logger._info), 3)
        self.assertEqual(logger._info[0], 'request classification: match')
        self.assertTrue(logger._info[1].startswith('forgetting via headers '))
        self.assertEqual(logger._info[2], 'no challenge app returned')
        self.assertEqual(len(logger._debug), 2)
        self.assertTrue(logger._debug[0].startswith(
                                        'challengers registered: ['))
        self.assertTrue(logger._debug[1].startswith(
                                        'challengers matched for '
                                        'classification "match": ['))

    def test_api_challenge_identifier_app_no_forget_headers(self):
        logger = DummyLogger()
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identity = {'login':'chris',
                    'password':'password',
                    'identifier': identifier}
        environ = _make_wsgi_environ()
        environ['repoze.who.identity'] = identity
        app = DummyApp()
        challenger = DummyChallenger(app)
        plugins = [ ('challenge', challenger) ]
        api = self._makeOne(environ=environ,
                            challengers=plugins,
                            request_classifier=lambda environ: 'match',
                            logger=logger,
                           )

        result = api.challenge('401 Unauthorized', [])

        self.assertEqual(result, app)
        self.assertEqual(environ['challenged'], app)
        self.assertEqual(identifier.forgotten, identity)
        self.assertEqual(len(logger._info), 3)
        self.assertEqual(logger._info[0], 'request classification: match')
        self.assertTrue(logger._info[1].startswith('forgetting via headers '))
        self.assertTrue(logger._info[2].startswith('challenger plugin '))
        self.assertTrue(logger._info[2].endswith(
                         '"challenge" returned an app'))
        self.assertEqual(len(logger._debug), 2)
        self.assertTrue(logger._debug[0].startswith(
                                        'challengers registered: ['))
        self.assertTrue(logger._debug[1].startswith(
                                        'challengers matched for '
                                        'classification "match": ['))

    def test_api_challenge_identifier_no_app_forget_headers(self):
        FORGET_HEADERS = [('X-testing-forget', 'Oubliez!')]
        logger = DummyLogger()
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials,
                                     forget_headers=FORGET_HEADERS)
        identity = {'login':'chris',
                    'password':'password',
                    'identifier': identifier}
        environ = _make_wsgi_environ()
        environ['repoze.who.identity'] = identity
        app = DummyApp()
        challenger = DummyChallenger(app)
        plugins = [ ('challenge', challenger) ]
        api = self._makeOne(environ=environ,
                            challengers=plugins,
                            request_classifier=lambda environ: 'match',
                            logger=logger,
                           )

        result = api.challenge('401 Unauthorized', [])

        self.assertEqual(result, app)
        self.assertEqual(environ['challenged'], app)
        self.assertEqual(challenger._challenged_with[3], FORGET_HEADERS)
        self.assertEqual(len(logger._info), 3)
        self.assertEqual(logger._info[0], 'request classification: match')
        self.assertTrue(logger._info[1].startswith(
                                        'forgetting via headers from'))
        self.assertTrue(logger._info[1].endswith(repr(FORGET_HEADERS)))
        self.assertTrue(logger._info[2].startswith('challenger plugin '))
        self.assertTrue(logger._info[2].endswith(
                         '"challenge" returned an app'))
        self.assertEqual(len(logger._debug), 2)
        self.assertTrue(logger._debug[0].startswith(
                                        'challengers registered: ['))
        self.assertTrue(logger._debug[1].startswith(
                                        'challengers matched for '
                                        'classification "match": ['))

    def test_api_challenge_w_multi_challengers_firstwins(self):
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identity = {'login':'chris',
                    'password':'password',
                    'identifier': identifier}
        environ = _make_wsgi_environ()
        environ['repoze.who.identity'] = identity
        app1 = DummyApp()
        app2 = DummyApp()
        challenger1 = DummyChallenger(app1)
        challenger2 = DummyChallenger(app2)
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        api = self._makeOne(environ=environ, challengers=plugins,
                            request_classifier=lambda environ: 'match')

        result = api.challenge('401 Unauthorized', [])

        self.assertIs(result, app1)
        self.assertIs(environ['challenged'], app1)
        self.assertEqual(identifier.forgotten, identity)

    def test_api_challenge_w_multi_challengers_skipnomatch_findimplicit(self):
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identity = {'login':'chris',
                    'password':'password',
                    'identifier': identifier}
        environ = _make_wsgi_environ()
        environ['repoze.who.identity'] = identity
        app1 = DummyApp()
        app2 = DummyApp()
        challenger1 = DummyChallenger(app1)
        challenger1.classifications = {interfaces.IChallenger:['nomatch']}
        challenger2 = DummyChallenger(app2)
        challenger2.classifications = {interfaces.IChallenger:None}
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        api = self._makeOne(environ=environ, challengers=plugins,
                            request_classifier=lambda environ: 'match')

        result = api.challenge('401 Unauthorized', [])

        self.assertIs(result, app2)
        self.assertIs(environ['challenged'], app2)
        self.assertEqual(identifier.forgotten, identity)

    def test_api_challenge_w_multi_challengers_skipnomatch_findexplicit(self):
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identity = {'login':'chris',
                    'password':'password',
                    'identifier': identifier}
        environ = _make_wsgi_environ()
        environ['repoze.who.identity'] = identity
        app1 = DummyApp()
        app2 = DummyApp()
        challenger1 = DummyChallenger(app1)
        challenger1.classifications = {interfaces.IChallenger:['nomatch']}
        challenger2 = DummyChallenger(app2)
        challenger2.classifications = {interfaces.IChallenger:['match']}
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        api = self._makeOne(environ=environ, challengers=plugins,
                            request_classifier=lambda environ: 'match')

        result = api.challenge('401 Unauthorized', [])

        self.assertIs(result, app2)
        self.assertIs(environ['challenged'], app2)
        self.assertEqual(identifier.forgotten, identity)

    def test_api_remember_identifier_plugin_returns_none(self):
        identity = {'identifier': DummyNoResultsIdentifier()}
        api = self._makeOne()
        headers = api.remember(identity=identity)
        self.assertEqual(tuple(headers), ())

    def test_api_remember_no_identity_passed_or_in_environ(self):
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        api = self._makeOne(environ=environ)
        self.assertEqual(len(api.remember()), 0)
        self.assertEqual(len(logger._info), 0)
        self.assertEqual(len(logger._debug), 0)

    def test_api_remember_no_identity_passed_but_in_environ(self):
        HEADERS = [('Foo', 'Bar'), ('Baz', 'Qux')]
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        environ['repoze.who.identity'] = {
            'identifier': DummyIdentifier(remember_headers=HEADERS)}
        api = self._makeOne(environ=environ, logger=logger)

        result = api.remember()

        self.assertEqual(result, HEADERS)
        self.assertEqual(len(logger._info), 2)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertTrue(logger._info[1].startswith(
                                        'remembering via headers from'))
        self.assertTrue(logger._info[1].endswith(repr(HEADERS)))
        self.assertEqual(len(logger._debug), 0)

    def test_api_remember_w_identity_passed_no_identifier(self):
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        api = self._makeOne(environ=environ, logger=logger)
        identity = {}

        result = api.remember(identity)

        self.assertEqual(len(result), 0)
        self.assertEqual(len(logger._info), 1)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertEqual(len(logger._debug), 0)

    def test_api_remember_w_identity_passed_w_identifier(self):
        HEADERS = [('Foo', 'Bar'), ('Baz', 'Qux')]
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        api = self._makeOne(environ=environ, logger=logger)
        identity = {'identifier': DummyIdentifier(remember_headers=HEADERS)}

        result = api.remember(identity)

        self.assertEqual(result, HEADERS)
        self.assertEqual(len(logger._info), 2)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertTrue(logger._info[1].startswith(
                                        'remembering via headers from'))
        self.assertTrue(logger._info[1].endswith(repr(HEADERS)))
        self.assertEqual(len(logger._debug), 0)

    def test_api_forget_identifier_plugin_returns_none(self):
        identity = {'identifier': DummyNoResultsIdentifier()}
        api = self._makeOne()

        result = api.forget(identity=identity)

        self.assertEqual(tuple(result), ())

    def test_api_forget_no_identity_passed_or_in_environ(self):
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        api = self._makeOne(environ=environ, logger=logger)

        result = api.forget()

        self.assertEqual(len(result), 0)
        self.assertEqual(len(logger._info), 1)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertEqual(len(logger._debug), 0)

    def test_api_forget_no_identity_passed_but_in_environ(self):
        HEADERS = [('Foo', 'Bar'), ('Baz', 'Qux')]
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        environ['repoze.who.identity'] = {
            'identifier': DummyIdentifier(forget_headers=HEADERS)}
        api = self._makeOne(environ=environ, logger=logger)

        result = api.forget()

        self.assertEqual(result, HEADERS)
        self.assertEqual(len(logger._info), 2)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertTrue(logger._info[1].startswith(
                                        'forgetting via headers from'))
        self.assertTrue(logger._info[1].endswith(repr(HEADERS)))
        self.assertEqual(len(logger._debug), 0)

    def test_api_forget_w_identity_passed_no_identifier(self):
        environ = _make_wsgi_environ()
        logger = DummyLogger()
        api = self._makeOne(environ=environ, logger=logger)
        identity = {}

        result = api.forget(identity=identity)

        self.assertEqual(len(result), 0)
        self.assertEqual(len(logger._info), 1)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertEqual(len(logger._debug), 0)

    def test_api_forget_w_identity_passed_w_identifier(self):
        HEADERS = [('Foo', 'Bar'), ('Baz', 'Qux')]
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        api = self._makeOne(environ=environ, logger=logger)
        identity = {'identifier': DummyIdentifier(forget_headers=HEADERS)}

        result = api.forget(identity=identity)

        self.assertEqual(result, HEADERS)
        self.assertEqual(len(logger._info), 2)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertTrue(logger._info[1].startswith(
                                        'forgetting via headers from'))
        self.assertTrue(logger._info[1].endswith(repr(HEADERS)))
        self.assertEqual(len(logger._debug), 0)

    def test_api_login_w_identifier_name_hit(self):
        REMEMBER_HEADERS = [('Foo', 'Bar'), ('Baz', 'Qux')]
        authenticator = DummyAuthenticator('chrisid')
        environ = _make_wsgi_environ()
        identifiers = [('bogus', DummyNoResultsIdentifier()),
                       ('valid', DummyIdentifier(
                                    remember_headers=REMEMBER_HEADERS)),
                      ]
        api = self._makeOne(identifiers=identifiers,
                            authenticators=[('authentic', authenticator)],
                            environ=environ)

        identity, headers = api.login({'login': 'chrisid'}, 'valid')

        self.assertEqual(identity['repoze.who.userid'], 'chrisid')
        self.assertEqual(headers, REMEMBER_HEADERS)

    def test_api_login_wo_identifier_name_hit(self):
        REMEMBER_HEADERS = [('Foo', 'Bar'), ('Baz', 'Qux')]
        authenticator = DummyAuthenticator('chrisid')
        environ = _make_wsgi_environ()
        identifiers = [('bogus', DummyIdentifier(
                                    remember_headers=REMEMBER_HEADERS[:1])),
                       ('valid', DummyIdentifier(
                                    remember_headers=REMEMBER_HEADERS[1:])),
                      ]
        api = self._makeOne(identifiers=identifiers,
                            authenticators=[('authentic', authenticator)],
                            environ=environ)

        identity, headers = api.login({'login': 'chrisid'})

        self.assertEqual(identity['repoze.who.userid'], 'chrisid')
        self.assertEqual(headers, REMEMBER_HEADERS)

    def test_api_login_w_identifier_name_miss(self):
        REMEMBER_HEADERS = [('Foo', 'Bar'), ('Baz', 'Qux')]
        FORGET_HEADERS = [('Spam', 'Blah')]
        authenticator = DummyFailAuthenticator()
        environ = _make_wsgi_environ()
        identifiers = [('bogus', DummyNoResultsIdentifier()),
                       ('valid', DummyIdentifier(
                                    remember_headers=REMEMBER_HEADERS,
                                    forget_headers=FORGET_HEADERS)),
                      ]
        api = self._makeOne(identifiers=identifiers,
                            authenticators=[('authentic', authenticator)],
                            environ=environ)

        identity, headers = api.login({'login': 'notchrisid'}, 'valid')

        self.assertEqual(identity, None)
        self.assertEqual(headers, FORGET_HEADERS)

    def test_api_logout_wo_identifier_name_miss(self):
        FORGET_HEADERS = [('Spam', 'Blah')]
        environ = _make_wsgi_environ()
        identifiers = [('valid', DummyIdentifier(
                                    forget_headers=FORGET_HEADERS[:1])),
                       ('bogus', DummyIdentifier(
                                    forget_headers=FORGET_HEADERS[1:])),
                      ]
        api = self._makeOne(identifiers=identifiers,
                            environ=environ)

        headers = api.logout()

        self.assertEqual(headers, FORGET_HEADERS)

    def test_api_logout_w_identifier_name(self):
        FORGET_HEADERS = [('Spam', 'Blah')]
        environ = _make_wsgi_environ()
        identifiers = [('bogus', DummyNoResultsIdentifier()),
                       ('valid', DummyIdentifier(
                                    forget_headers=FORGET_HEADERS)),
                      ]
        api = self._makeOne(identifiers=identifiers,
                            environ=environ)

        headers = api.logout('valid')

        self.assertEqual(headers, FORGET_HEADERS)

    def test_api_logout_wo_identifier_name(self):
        FORGET_HEADERS = [('Spam', 'Blah')]
        authenticator = DummyFailAuthenticator()
        environ = _make_wsgi_environ()
        identifiers = [('bogus', DummyNoResultsIdentifier()),
                       ('valid', DummyIdentifier(
                                    forget_headers=FORGET_HEADERS)),
                      ]
        api = self._makeOne(identifiers=identifiers,
                            authenticators=[('authentic', authenticator)],
                            environ=environ)

        headers = api.logout()

        self.assertEqual(headers, FORGET_HEADERS)

    def test_api_logout_removes_repoze_who_identity(self):
        authenticator = DummyFailAuthenticator()
        environ = _make_wsgi_environ()
        environ['repoze.who.identity'] = 'identity'
        identifiers = [('valid', DummyNoResultsIdentifier())]
        api = self._makeOne(identifiers=identifiers,
                            authenticators=[('authentic', authenticator)],
                            environ=environ)

        api.logout()

        self.assertFalse('repoze.who.identity' in environ)

    def test_api__identify_success(self):
        environ = _make_wsgi_environ()
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('i', identifier) ]
        api = self._makeOne(environ=environ, identifiers=identifiers)

        results = api._identify()

        self.assertEqual(len(results), 1)
        new_identifier, identity = results[0]
        self.assertEqual(new_identifier, identifier)
        self.assertEqual(identity['login'], 'chris')
        self.assertEqual(identity['password'], 'password')

    def test_api__identify_success_empty_identity(self):
        environ = _make_wsgi_environ()
        identifier = DummyIdentifier({})
        identifiers = [ ('i', identifier) ]
        api = self._makeOne(environ=environ, identifiers=identifiers)

        results = api._identify()

        self.assertEqual(len(results), 1)
        new_identifier, identity = results[0]
        self.assertEqual(new_identifier, identifier)
        self.assertEqual(identity, {})

    def test_api__identify_fail(self):
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        plugin = DummyNoResultsIdentifier()
        plugins = [ ('dummy', plugin) ]
        api = self._makeOne(environ=environ,
                            identifiers=plugins,
                            logger=logger)

        results = api._identify()

        self.assertEqual(len(results), 0)
        self.assertEqual(len(logger._info), 1)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertEqual(len(logger._debug), 4)
        self.assertTrue(logger._debug[0].startswith(
                                        'identifier plugins registered: ['))
        self.assertTrue(logger._debug[1].startswith(
                                        'identifier plugins matched for '
                                        'classification "browser": ['))
        self.assertTrue(logger._debug[2].startswith(
                                        'no identity returned from <'))
        self.assertTrue(logger._debug[2].endswith('> (None)'))
        self.assertEqual(logger._debug[3], 'identities found: []')

    def test_api__identify_success_skip_noresults(self):
        environ = _make_wsgi_environ()
        api = self._makeOne()
        plugin1 = DummyNoResultsIdentifier()
        credentials = {'login':'chris', 'password':'password'}
        plugin2 = DummyIdentifier(credentials)
        plugins = [ ('identifier1', plugin1), ('identifier2', plugin2) ]
        api = self._makeOne(environ=environ, identifiers=plugins)

        results = api._identify()

        self.assertEqual(len(results), 1)
        new_identifier, identity = results[0]
        self.assertEqual(new_identifier, plugin2)
        self.assertEqual(identity['login'], 'chris')
        self.assertEqual(identity['password'], 'password')

    def test_api__identify_success_multiresults(self):
        environ = _make_wsgi_environ()
        api = self._makeOne()
        plugin1 = DummyIdentifier({'login':'fred','password':'fred'})
        plugin2 = DummyIdentifier({'login':'bob','password':'bob'})
        plugins = [ ('identifier1', plugin1), ('identifier2', plugin2) ]
        api = self._makeOne(environ=environ, identifiers=plugins)

        results = api._identify()

        self.assertEqual(len(results), 2)

        new_identifier, identity = results[0]
        self.assertEqual(new_identifier, plugin1)
        self.assertEqual(identity['login'], 'fred')
        self.assertEqual(identity['password'], 'fred')

        new_identifier, identity = results[1]
        self.assertEqual(new_identifier, plugin2)
        self.assertEqual(identity['login'], 'bob')
        self.assertEqual(identity['password'], 'bob')

    def test_api__identify_find_implicit_classifier(self):
        environ = _make_wsgi_environ()
        api = self._makeOne()
        plugin1 = DummyIdentifier({'login':'fred','password':'fred'})
        plugin1.classifications = {interfaces.IIdentifier:['nomatch']}
        plugin2 = DummyIdentifier({'login':'bob','password':'bob'})
        plugins = [ ('identifier1', plugin1),  ('identifier2', plugin2) ]
        api = self._makeOne(environ=environ, identifiers=plugins,
                            request_classifier=lambda environ: 'match')

        results = api._identify()

        self.assertEqual(len(results), 1)
        plugin, creds = results[0]
        self.assertEqual(creds['login'], 'bob')
        self.assertEqual(creds['password'], 'bob')
        self.assertEqual(plugin, plugin2)

    def test_api__identify_find_explicit_classifier(self):
        environ = _make_wsgi_environ()
        plugin1 = DummyIdentifier({'login':'fred','password':'fred'})
        plugin1.classifications = {interfaces.IIdentifier:['nomatch']}
        plugin2 = DummyIdentifier({'login':'bob','password':'bob'})
        plugin2.classifications = {interfaces.IIdentifier:['match']}
        plugins= [ ('identifier1', plugin1), ('identifier2', plugin2) ]
        api = self._makeOne(environ=environ, identifiers=plugins,
                            request_classifier=lambda environ: 'match')

        results = api._identify()

        self.assertEqual(len(results), 1)
        plugin, creds = results[0]
        self.assertEqual(creds['login'], 'bob')
        self.assertEqual(creds['password'], 'bob')
        self.assertEqual(plugin, plugin2)

    def test_api__authenticate_success(self):
        environ = _make_wsgi_environ()
        plugin1 = DummyAuthenticator('a')
        plugins = [ ('identifier1', plugin1) ]
        api = self._makeOne(environ=environ, authenticators=plugins)
        identities = [ (None, {'login':'chris', 'password':'password'}) ]

        results = api._authenticate(identities)

        self.assertEqual(len(results), 1)
        result = results[0]

        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0,0))
        self.assertEqual(authenticator, plugin1)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'a')

    def test_api__authenticate_fail(self):
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        # no authenticators
        api = self._makeOne(environ=environ, logger=logger)
        identities = [ (None, {'login':'chris', 'password':'password'}) ]

        result = api._authenticate(identities)

        self.assertEqual(len(result), 0)
        self.assertEqual(len(logger._info), 1)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertEqual(len(logger._debug), 3)
        self.assertEqual(logger._debug[0], 'authenticator plugins '
                                           'registered: []')
        self.assertEqual(logger._debug[1], 'authenticator plugins matched '
                                           'for classification "browser": []')
        self.assertEqual(logger._debug[2], 'identities authenticated: []')

    def test_api__authenticate_success_skip_fail(self):
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        plugin1 = DummyFailAuthenticator()
        plugin2 = DummyAuthenticator()
        plugins = [ ('dummy1', plugin1), ('dummy2', plugin2) ]
        api = self._makeOne(environ=environ, authenticators=plugins, logger=logger)
        creds = {'login':'chris', 'password':'password'}
        identities = [ (None, {'login':'chris', 'password':'password'}) ]

        results = api._authenticate(identities)

        self.assertEqual(len(results), 1)
        result = results[0]

        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (1,0))
        self.assertEqual(authenticator, plugin2)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris')

        self.assertEqual(len(logger._info), 1)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertEqual(len(logger._debug), 5)
        self.assertTrue(logger._debug[0].startswith(
                                        'authenticator plugins registered: ['))
        self.assertTrue(logger._debug[1].startswith(
                                        'authenticator plugins matched for '
                                        'classification "browser": ['))
        self.assertTrue(logger._debug[2].startswith('no userid returned from'))
        self.assertTrue(logger._debug[3].startswith('userid returned from'))
        self.assertTrue(logger._debug[3].endswith('"chris"'))
        self.assertTrue(logger._debug[4].startswith(
                                         'identities authenticated: [((1, 0),'))

    def test_api__authenticate_success_multiresult(self):
        logger = DummyLogger()
        environ = _make_wsgi_environ()
        plugin1 = DummyAuthenticator('chris_id1')
        plugin2 = DummyAuthenticator('chris_id2')
        plugins = [ ('dummy1',plugin1), ('dummy2',plugin2) ]
        api = self._makeOne(environ=environ,
                            authenticators=plugins, logger=logger)
        creds = {'login':'chris', 'password':'password'}
        identities = [ (None, {'login':'chris', 'password':'password'}) ]

        results = api._authenticate(identities)

        self.assertEqual(len(results), 2)
        result = results[0]

        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0,0,))
        self.assertEqual(authenticator, plugin1)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id1')

        result = results[1]
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (1,0))
        self.assertEqual(authenticator, plugin2)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id2')

        self.assertEqual(len(logger._info), 1)
        self.assertEqual(logger._info[0], 'request classification: browser')
        self.assertEqual(len(logger._debug), 5)
        self.assertTrue(logger._debug[0].startswith(
                                        'authenticator plugins registered: ['))
        self.assertTrue(logger._debug[1].startswith(
                                        'authenticator plugins matched for '
                                        'classification "browser": ['))
        self.assertTrue(logger._debug[2].startswith('userid returned from'))
        self.assertTrue(logger._debug[2].endswith('"chris_id1"'))
        self.assertTrue(logger._debug[3].startswith('userid returned from'))
        self.assertTrue(logger._debug[3].endswith('"chris_id2"'))
        self.assertTrue(logger._debug[4].startswith(
                                         'identities authenticated: [((0, 0),')
                                         )

    def test_api__authenticate_find_implicit_classifier(self):
        environ = _make_wsgi_environ()
        plugin1 = DummyAuthenticator('chris_id1')
        plugin1.classifications = {interfaces.IAuthenticator:['nomatch']}
        plugin2 = DummyAuthenticator('chris_id2')
        plugins = [ ('auth1', plugin1), ('auth2', plugin2) ]
        api = self._makeOne(environ=environ, authenticators=plugins,
                            request_classifier=lambda environ: 'match')
        identities = [ (None, {'login':'chris', 'password':'password'}) ]

        results = api._authenticate(identities)

        self.assertEqual(len(results), 1)
        result = results[0]

        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0,0))
        self.assertEqual(authenticator, plugin2)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id2')

    def test_api__authenticate_find_explicit_classifier(self):
        environ = _make_wsgi_environ()
        plugin1 = DummyAuthenticator('chris_id1')
        plugin1.classifications = {interfaces.IAuthenticator:['nomatch']}
        plugin2 = DummyAuthenticator('chris_id2')
        plugin2.classifications = {interfaces.IAuthenticator:['match']}
        plugins = [ ('auth1', plugin1), ('auth2', plugin2) ]
        api = self._makeOne(environ=environ, authenticators=plugins,
                            request_classifier=lambda environ: 'match')
        identities = [ (None, {'login':'chris', 'password':'password'}) ]

        results = api._authenticate(identities)

        self.assertEqual(len(results), 1)
        result = results[0]

        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0, 0))
        self.assertEqual(authenticator, plugin2)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id2')

    def test_api__authenticate_user_null_but_not_none(self):
        environ = _make_wsgi_environ()
        plugin1 = DummyAuthenticator(0)
        plugins = [ ('identifier1', plugin1) ]
        api = self._makeOne(environ=environ, authenticators=plugins)
        identities = [ (None, {'login':'chris', 'password':'password'}) ]

        results = api._authenticate(identities)

        self.assertEqual(len(results), 1)
        result = results[0]

        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0,0))
        self.assertEqual(authenticator, plugin1)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 0)

    def test_api__add_metadata(self):
        environ = _make_wsgi_environ()
        plugin1 = DummyMDProvider({'foo':'bar'})
        plugin2 = DummyMDProvider({'fuz':'baz'})
        plugins = [ ('meta1', plugin1), ('meta2', plugin2) ]
        api = self._makeOne(environ=environ, mdproviders=plugins)
        identity = {}

        api._add_metadata(identity)

        self.assertEqual(identity['foo'], 'bar')
        self.assertEqual(identity['fuz'], 'baz')

    def test_api__add_metadata_w_classification(self):
        environ = _make_wsgi_environ()
        plugin1 = DummyMDProvider({'foo':'bar'})
        plugin2 = DummyMDProvider({'fuz':'baz'})
        plugin2.classifications = {interfaces.IMetadataProvider:['foo']}
        plugins = [ ('meta1', plugin1), ('meta2', plugin2) ]
        api = self._makeOne(environ=environ, mdproviders=plugins)
        identity = {}

        api._add_metadata(identity)

        self.assertEqual(identity['foo'], 'bar')
        self.assertEqual(identity.get('fuz'), None)


class TestIdentityDict(unittest.TestCase):

    def test_identity_str(self):
        identity = api_module.Identity(foo=1)
        self.assertTrue(str(identity).startswith('<repoze.who identity'))
        self.assertEqual(identity['foo'], 1)

    def test_identity_repr(self):
        identity = api_module.Identity(foo=1)
        self.assertTrue(str(identity).startswith('<repoze.who identity'))
        self.assertEqual(identity['foo'], 1)



class DummyIdentifier(object):
    forgotten = False
    remembered = False

    def __init__(self, credentials=None,
                 remember_headers=(), forget_headers=()):
        self.credentials = credentials
        self.remember_headers = remember_headers
        self.forget_headers = forget_headers

    def identify(self, environ):
        return self.credentials

    def forget(self, environ, identity):
        self.forgotten = identity
        return self.forget_headers

    def remember(self, environ, identity):
        self.remembered = identity
        return self.remember_headers


class DummyNoResultsIdentifier(object):

    def identify(self, environ):
        return None

    def remember(self, *arg, **kw):
        return ()

    def forget(self, *arg, **kw):
        return ()


class DummyAuthenticator(object):
    def __init__(self, userid=None):
        self.userid = userid

    def authenticate(self, environ, credentials):
        if self.userid is None:
            return credentials['login']
        return self.userid


class DummyFailAuthenticator(object):
    def authenticate(self, environ, credentials):
        return None


class DummyChallenger(object):
    _challenged_with = None
    def __init__(self, app=None):
        self.app = app

    def challenge(self, environ, status, app_headers, forget_headers):
        environ['challenged'] = self.app
        self._challenged_with = (environ, status, app_headers, forget_headers)
        return self.app


class DummyMDProvider(object):
    def __init__(self, metadata=None):
        self._metadata = metadata

    def add_metadata(self, environ, identity):
        return identity.update(self._metadata)


class DummyMultiPlugin(object):
    pass


class DummyRequestClassifier(object):
    def __call__(self, environ):
        return 'browser'


class DummyChallengeDecider(object):
    pass


class DummyLogger(object):
    _info = _debug = ()
    def info(self, msg):
        self._info += (msg,)
    def debug(self, msg):
        self._debug += (msg,)

class DummyApp(object):
    environ = None
