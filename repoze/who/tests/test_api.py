import unittest

class Test_get_api(unittest.TestCase):

    def _callFUT(self, environ):
        from repoze.who.api import get_api
        return get_api(environ)

    def test___call___empty_environ(self):
        from repoze.who.api import API
        environ = {}
        api = self._callFUT(environ)
        self.failUnless(api is None)

    def test___call___w_api_in_environ(self):
        expected = object()
        environ = {'repoze.who.api': expected}
        api = self._callFUT(environ)
        self.failUnless(api is expected)

class APIFactoryTests(unittest.TestCase):

    def _getTargetClass(self):
        from repoze.who.api import APIFactory
        return APIFactory

    def _makeOne(self,
                 plugins=None,
                 identifiers=None,
                 authenticators=None,
                 challengers=None,
                 mdproviders=None,
                 request_classifier=None,
                 challenge_decider=None,
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
        return self._getTargetClass()(identifiers,
                                      authenticators,
                                      challengers,
                                      mdproviders,
                                      request_classifier,
                                      challenge_decider,
                                      logger,
                                     )

    def test_class_conforms_to_IAPIFactory(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IAPIFactory
        verifyClass(IAPIFactory, self._getTargetClass())

    def test_instance_conforms_to_IAPIFactory(self):
        from zope.interface.verify import verifyObject
        from repoze.who.interfaces import IAPIFactory
        verifyObject(IAPIFactory, self._makeOne())

    def test_ctor_defaults(self):
        factory = self._makeOne()
        self.assertEqual(len(factory.identifiers), 0)
        self.assertEqual(len(factory.authenticators), 0)
        self.assertEqual(len(factory.challengers), 0)
        self.assertEqual(len(factory.mdproviders), 0)
        self.assertEqual(factory.request_classifier, None)
        self.assertEqual(factory.challenge_decider, None)
        self.assertEqual(factory.logger, None)

    def test___call___empty_environ(self):
        from repoze.who.api import API
        environ = {}
        factory = self._makeOne()
        api = factory(environ)
        self.failUnless(isinstance(api, API))
        self.failUnless(environ['repoze.who.api'] is api)

    def test___call___w_api_in_environ(self):
        expected = object()
        environ = {'repoze.who.api': expected}
        factory = self._makeOne()
        api = factory(environ)
        self.failUnless(api is expected)


class TestMakeRegistries(unittest.TestCase):

    def _callFUT(self, identifiers, authenticators, challengers, mdproviders):
        from repoze.who.api import make_registries
        return make_registries(identifiers, authenticators,
                               challengers, mdproviders)

    def test_empty(self):
        iface_reg, name_reg = self._callFUT([], [], [], [])
        self.assertEqual(iface_reg, {})
        self.assertEqual(name_reg, {})

    def test_brokenimpl(self):
        self.assertRaises(ValueError, self._callFUT,
                          [(None, object())], [], [], [])

    def test_ok(self):
        from repoze.who.interfaces import IIdentifier
        from repoze.who.interfaces import IAuthenticator
        from repoze.who.interfaces import IChallenger
        from repoze.who.interfaces import IMetadataProvider
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
        iface_reg, name_reg = self._callFUT(identifiers, authenticators,
                                            challengers, mdproviders)
        self.assertEqual(iface_reg[IIdentifier], [dummy_id1, dummy_id2])
        self.assertEqual(iface_reg[IAuthenticator], [dummy_auth])
        self.assertEqual(iface_reg[IChallenger], [dummy_challenger])
        self.assertEqual(iface_reg[IMetadataProvider], [dummy_mdprovider])
        self.assertEqual(name_reg['id1'], dummy_id1)
        self.assertEqual(name_reg['id2'], dummy_id2)
        self.assertEqual(name_reg['auth'], dummy_auth)
        self.assertEqual(name_reg['challenger'], dummy_challenger)
        self.assertEqual(name_reg['mdprovider'], dummy_mdprovider)

class TestMatchClassification(unittest.TestCase):

    def _getFUT(self):
        from repoze.who.api import match_classification
        return match_classification

    def test_match_classification(self):
        f = self._getFUT()
        from repoze.who.interfaces import IIdentifier
        from repoze.who.interfaces import IChallenger
        from repoze.who.interfaces import IAuthenticator
        multi1 = DummyMultiPlugin()
        multi2 = DummyMultiPlugin()
        multi1.classifications = {IIdentifier:('foo', 'bar'),
                                  IChallenger:('buz',),
                                  IAuthenticator:None}
        multi2.classifications = {IIdentifier:('foo', 'baz', 'biz')}
        plugins = (multi1, multi2)
        # specific
        self.assertEqual(f(IIdentifier, plugins, 'foo'), [multi1, multi2])
        self.assertEqual(f(IIdentifier, plugins, 'bar'), [multi1])
        self.assertEqual(f(IIdentifier, plugins, 'biz'), [multi2])
        # any for multi2
        self.assertEqual(f(IChallenger, plugins, 'buz'), [multi1, multi2])
        # any for either
        self.assertEqual(f(IAuthenticator, plugins, 'buz'), [multi1, multi2])

class APITests(unittest.TestCase):

    def _getTargetClass(self):
        from repoze.who.api import API
        return API

    def _makeOne(self,
                 identifiers=None,
                 authenticators=None,
                 challengers=None,
                 classifier=None,
                 mdproviders=None,
                 challenge_decider=None,
                 logger=None
                 ):
        if identifiers is None:
            identifiers = []
        if authenticators is None:
            authenticators = []
        if challengers is None:
            challengers = []
        if classifier is None:
            classifier = DummyRequestClassifier()
        if mdproviders is None:
            mdproviders = []
        if challenge_decider is None:
            challenge_decider = DummyChallengeDecider()
        api = self._getTargetClass()(identifiers,
                                     authenticators,
                                     challengers,
                                     mdproviders,
                                     classifier,
                                     challenge_decider,
                                     logger,
                                    )
        return api

    def _makeEnviron(self):
        return {'wsgi.version': (1,0)}

    def test_accepts_logger_instance(self):
        import logging
        logger = logging.Logger('something')
        logger.setLevel(logging.INFO)
        api = self._makeOne(logger=logger)
        self.failUnless(api.logger is logger)

    def test_identify_success(self):
        environ = self._makeEnviron()
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        identifiers = [ ('i', identifier) ]
        api = self._makeOne(identifiers=identifiers)
        results = api.identify(environ, None)
        self.assertEqual(len(results), 1)
        new_identifier, identity = results[0]
        self.assertEqual(new_identifier, identifier)
        self.assertEqual(identity['login'], 'chris')
        self.assertEqual(identity['password'], 'password')

    def test_identify_success_empty_identity(self):
        environ = self._makeEnviron()
        identifier = DummyIdentifier({})
        identifiers = [ ('i', identifier) ]
        api = self._makeOne(identifiers=identifiers)
        results = api.identify(environ, None)
        self.assertEqual(len(results), 1)
        new_identifier, identity = results[0]
        self.assertEqual(new_identifier, identifier)
        self.assertEqual(identity, {})

    def test_identify_fail(self):
        environ = self._makeEnviron()
        plugin = DummyNoResultsIdentifier()
        plugins = [ ('dummy', plugin) ]
        api = self._makeOne(identifiers=plugins)
        results = api.identify(environ, None)
        self.assertEqual(len(results), 0)

    def test_identify_success_skip_noresults(self):
        environ = self._makeEnviron()
        api = self._makeOne()
        plugin1 = DummyNoResultsIdentifier()
        credentials = {'login':'chris', 'password':'password'}
        plugin2 = DummyIdentifier(credentials)
        plugins = [ ('identifier1', plugin1), ('identifier2', plugin2) ]
        api = self._makeOne(identifiers=plugins)
        results = api.identify(environ, None)
        self.assertEqual(len(results), 1)
        new_identifier, identity = results[0]
        self.assertEqual(new_identifier, plugin2)
        self.assertEqual(identity['login'], 'chris')
        self.assertEqual(identity['password'], 'password')

    def test_identify_success_multiresults(self):
        environ = self._makeEnviron()
        api = self._makeOne()
        plugin1 = DummyIdentifier({'login':'fred','password':'fred'})
        plugin2 = DummyIdentifier({'login':'bob','password':'bob'})
        plugins = [ ('identifier1', plugin1), ('identifier2', plugin2) ]
        api = self._makeOne(identifiers=plugins)
        results = api.identify(environ, None)
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
        api = self._makeOne()
        plugin1 = DummyIdentifier({'login':'fred','password':'fred'})
        from repoze.who.interfaces import IIdentifier
        plugin1.classifications = {IIdentifier:['nomatch']}
        plugin2 = DummyIdentifier({'login':'bob','password':'bob'})
        plugins = [ ('identifier1', plugin1),  ('identifier2', plugin2) ]
        api = self._makeOne(identifiers=plugins)
        results = api.identify(environ, 'match')
        self.assertEqual(len(results), 1)
        plugin, creds = results[0]
        self.assertEqual(creds['login'], 'bob')
        self.assertEqual(creds['password'], 'bob')
        self.assertEqual(plugin, plugin2)

    def test_identify_find_explicit_classifier(self):
        environ = self._makeEnviron()
        from repoze.who.interfaces import IIdentifier
        plugin1 = DummyIdentifier({'login':'fred','password':'fred'})
        plugin1.classifications = {IIdentifier:['nomatch']}
        plugin2 = DummyIdentifier({'login':'bob','password':'bob'})
        plugin2.classifications = {IIdentifier:['match']}
        plugins= [ ('identifier1', plugin1), ('identifier2', plugin2) ]
        api = self._makeOne(identifiers=plugins)
        results = api.identify(environ, 'match')
        self.assertEqual(len(results), 1)
        plugin, creds = results[0]
        self.assertEqual(creds['login'], 'bob')
        self.assertEqual(creds['password'], 'bob')
        self.assertEqual(plugin, plugin2)

    def test_authenticate_success(self):
        environ = self._makeEnviron()
        plugin1 = DummyAuthenticator('a')
        plugins = [ ('identifier1', plugin1) ]
        api = self._makeOne(authenticators=plugins)
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = api.authenticate(environ, None, identities)
        self.assertEqual(len(results), 1)
        result = results[0]
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0,0))
        self.assertEqual(authenticator, plugin1)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'a')

    def test_authenticate_fail(self):
        environ = self._makeEnviron()
        api = self._makeOne() # no authenticators
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        result = api.authenticate(environ, None, identities)
        self.assertEqual(len(result), 0)

    def test_authenticate_success_skip_fail(self):
        environ = self._makeEnviron()
        api = self._makeOne()
        plugin1 = DummyFailAuthenticator()
        plugin2 = DummyAuthenticator()
        plugins = [ ('dummy1', plugin1), ('dummy2', plugin2) ]
        api = self._makeOne(authenticators=plugins)
        creds = {'login':'chris', 'password':'password'}
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = api.authenticate(environ, None, identities)
        self.assertEqual(len(results), 1)
        result = results[0]
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (1,0))
        self.assertEqual(authenticator, plugin2)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris')

    def test_authenticate_success_multiresult(self):
        environ = self._makeEnviron()
        api = self._makeOne()
        plugin1 = DummyAuthenticator('chris_id1')
        plugin2 = DummyAuthenticator('chris_id2')
        plugins = [ ('dummy1',plugin1), ('dummy2',plugin2) ]
        api = self._makeOne(authenticators=plugins)
        creds = {'login':'chris', 'password':'password'}
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = api.authenticate(environ, None, identities)
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

    def test_authenticate_find_implicit_classifier(self):
        environ = self._makeEnviron()
        api = self._makeOne()
        plugin1 = DummyAuthenticator('chris_id1')
        from repoze.who.interfaces import IAuthenticator
        plugin1.classifications = {IAuthenticator:['nomatch']}
        plugin2 = DummyAuthenticator('chris_id2')
        plugins = [ ('auth1', plugin1), ('auth2', plugin2) ]
        api = self._makeOne(authenticators = plugins)
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = api.authenticate(environ, 'match', identities)
        self.assertEqual(len(results), 1)
        result = results[0]
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0,0))
        self.assertEqual(authenticator, plugin2)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id2')

    def test_authenticate_find_explicit_classifier(self):
        environ = self._makeEnviron()
        api = self._makeOne()
        from repoze.who.interfaces import IAuthenticator
        plugin1 = DummyAuthenticator('chris_id1')
        plugin1.classifications = {IAuthenticator:['nomatch']}
        plugin2 = DummyAuthenticator('chris_id2')
        plugin2.classifications = {IAuthenticator:['match']}
        plugins = [ ('auth1', plugin1), ('auth2', plugin2) ]
        api = self._makeOne(authenticators = plugins)
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = api.authenticate(environ, 'match', identities)
        self.assertEqual(len(results), 1)
        result = results[0]
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0, 0))
        self.assertEqual(authenticator, plugin2)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id2')

    def test_authenticate_user_null_but_not_none(self):
        environ = self._makeEnviron()
        plugin1 = DummyAuthenticator(0)
        plugins = [ ('identifier1', plugin1) ]
        api = self._makeOne(authenticators=plugins)
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = api.authenticate(environ, None, identities)
        self.assertEqual(len(results), 1)
        result = results[0]
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0,0))
        self.assertEqual(authenticator, plugin1)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 0)

    def test_authenticate_success_multiresult_one_preauthenticated(self):
        environ = self._makeEnviron()
        api = self._makeOne()
        preauth = DummyIdentifier({'repoze.who.userid':'preauthenticated'})
        plugin1 = DummyAuthenticator('chris_id1')
        plugin2 = DummyAuthenticator('chris_id2')
        plugins = [ ('dummy1',plugin1), ('dummy2',plugin2) ]
        api = self._makeOne(authenticators=plugins)
        creds = {'login':'chris', 'password':'password'}
        identities = [ (None, {'login':'chris', 'password':'password'}),
                       (preauth, preauth.credentials) ]
        results = api.authenticate(environ, None, identities)
        self.assertEqual(len(results), 3)
        result = results[0]
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0,0,))
        self.assertEqual(authenticator, None)
        self.assertEqual(identifier, preauth)
        self.assertEqual(creds['repoze.who.userid'], 'preauthenticated')
        self.assertEqual(userid, 'preauthenticated')
        result = results[1]
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0,1))
        self.assertEqual(authenticator, plugin1)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id1')
        result = results[2]
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (1,1))
        self.assertEqual(authenticator, plugin2)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id2')

    def test_challenge_noidentifier_noapp(self):
        environ = self._makeEnviron()
        challenger = DummyChallenger()
        plugins = [ ('challenge', challenger) ]
        api = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        app = api.challenge(environ, 'match', '401 Unauthorized',
                           [], None, identity)
        self.assertEqual(app, None)
        self.assertEqual(environ['challenged'], app)

    def test_challenge_noidentifier_withapp(self):
        environ = self._makeEnviron()
        app = DummyApp()
        challenger = DummyChallenger(app)
        plugins = [ ('challenge', challenger) ]
        api = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = api.challenge(environ, 'match', '401 Unauthorized',
                               [], None, identity)
        self.assertEqual(result, app)
        self.assertEqual(environ['challenged'], app)

    def test_challenge_identifier_noapp(self):
        environ = self._makeEnviron()
        challenger = DummyChallenger()
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        plugins = [ ('challenge', challenger) ]
        api = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = api.challenge(environ, 'match', '401 Unauthorized',
                              [], identifier, identity)
        self.assertEqual(result, None)
        self.assertEqual(environ['challenged'], None)
        self.assertEqual(identifier.forgotten, identity)

    def test_challenge_identifier_app(self):
        environ = self._makeEnviron()
        app = DummyApp()
        challenger = DummyChallenger(app)
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        plugins = [ ('challenge', challenger) ]
        api = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = api.challenge(environ, 'match', '401 Unauthorized',
                               [], identifier, identity)
        self.assertEqual(result, app)
        self.assertEqual(environ['challenged'], app)
        self.assertEqual(identifier.forgotten, identity)

    def test_challenge_identifier_forget_headers(self):
        FORGET_HEADERS = [('X-testing-forget', 'Oubliez!')]
        environ = self._makeEnviron()
        app = DummyApp()
        challenger = DummyChallenger(app)
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials,
                                     forget_headers=FORGET_HEADERS)
        plugins = [ ('challenge', challenger) ]
        api = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = api.challenge(environ, 'match', '401 Unauthorized',
                               [], identifier, identity)

    def test_multi_challenge_firstwins(self):
        environ = self._makeEnviron()
        app1 = DummyApp()
        app2 = DummyApp()
        challenger1 = DummyChallenger(app1)
        challenger2 = DummyChallenger(app2)
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        api = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = api.challenge(environ, 'match', '401 Unauthorized',
                              [], identifier, identity)
        self.assertEqual(result, app1)
        self.assertEqual(environ['challenged'], app1)
        self.assertEqual(identifier.forgotten, identity)

    def test_multi_challenge_skipnomatch_findimplicit(self):
        environ = self._makeEnviron()
        app1 = DummyApp()
        app2 = DummyApp()
        from repoze.who.interfaces import IChallenger
        challenger1 = DummyChallenger(app1)
        challenger1.classifications = {IChallenger:['nomatch']}
        challenger2 = DummyChallenger(app2)
        challenger2.classifications = {IChallenger:None}
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        api = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = api.challenge(environ, 'match', '401 Unauthorized',
                               [], identifier, identity)
        self.assertEqual(result, app2)
        self.assertEqual(environ['challenged'], app2)
        self.assertEqual(identifier.forgotten, identity)

    def test_multi_challenge_skipnomatch_findexplicit(self):
        environ = self._makeEnviron()
        app1 = DummyApp()
        app2 = DummyApp()
        from repoze.who.interfaces import IChallenger
        challenger1 = DummyChallenger(app1)
        challenger1.classifications = {IChallenger:['nomatch']}
        challenger2 = DummyChallenger(app2)
        challenger2.classifications = {IChallenger:['match']}
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        api = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = api.challenge(environ, 'match', '401 Unauthorized',
                               [], identifier, identity)
        self.assertEqual(result, app2)
        self.assertEqual(environ['challenged'], app2)
        self.assertEqual(identifier.forgotten, identity)

    def test_add_metadata(self):
        environ = self._makeEnviron()
        plugin1 = DummyMDProvider({'foo':'bar'})
        plugin2 = DummyMDProvider({'fuz':'baz'})
        plugins = [ ('meta1', plugin1), ('meta2', plugin2) ]
        api = self._makeOne(mdproviders=plugins)
        classification = ''
        identity = {}
        results = api.add_metadata(environ, classification, identity)
        self.assertEqual(identity['foo'], 'bar')
        self.assertEqual(identity['fuz'], 'baz')

    def test_add_metadata_w_classification(self):
        environ = self._makeEnviron()
        plugin1 = DummyMDProvider({'foo':'bar'})
        plugin2 = DummyMDProvider({'fuz':'baz'})
        from repoze.who.interfaces import IMetadataProvider
        plugin2.classifications = {IMetadataProvider:['foo']}
        plugins = [ ('meta1', plugin1), ('meta2', plugin2) ]
        api = self._makeOne(mdproviders=plugins)
        classification = 'monkey'
        identity = {}
        api.add_metadata(environ, classification, identity)
        self.assertEqual(identity['foo'], 'bar')
        self.assertEqual(identity.get('fuz'), None)





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


class DummyMultiPlugin:
    pass


class DummyRequestClassifier:
    def __call__(self, environ):
        return 'browser'


class DummyChallengeDecider:
    def __call__(self, environ, status, headers):
        if status.startswith('401 '):
            return True


class DummyApp:
    environ = None
    def __call__(self, environ, start_response):
        self.environ = environ
        return []
