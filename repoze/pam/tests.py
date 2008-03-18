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
                 mdproviders=None,                 
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

    def test_identify_success_empty_identity(self):
        environ = self._makeEnviron()
        identifier = DummyIdentifier({})
        identifiers = [ ('i', identifier) ]
        mw = self._makeOne(identifiers=identifiers)
        results = mw.identify(environ, None)
        self.assertEqual(len(results), 1)
        new_identifier, identity = results[0]
        self.assertEqual(new_identifier, identifier)
        self.assertEqual(identity, {})

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
        from repoze.pam.interfaces import IIdentifier
        plugin1.classifications = {IIdentifier:['nomatch']}
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
        from repoze.pam.interfaces import IIdentifier
        plugin1 = DummyIdentifier({'login':'fred','password':'fred'})
        plugin1.classifications = {IIdentifier:['nomatch']}
        plugin2 = DummyIdentifier({'login':'bob','password':'bob'})
        plugin2.classifications = {IIdentifier:['match']}
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
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0,0))
        self.assertEqual(authenticator, plugin1)
        self.assertEqual(identifier, None)
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
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (1,0))
        self.assertEqual(authenticator, plugin2)
        self.assertEqual(identifier, None)
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
        mw = self._makeOne()
        plugin1 = DummyAuthenticator('chris_id1')
        from repoze.pam.interfaces import IAuthenticator
        plugin1.classifications = {IAuthenticator:['nomatch']}
        plugin2 = DummyAuthenticator('chris_id2')
        plugins = [ ('auth1', plugin1), ('auth2', plugin2) ]
        mw = self._makeOne(authenticators = plugins)
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = mw.authenticate(environ, 'match', identities)
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
        mw = self._makeOne()
        from repoze.pam.interfaces import IAuthenticator
        plugin1 = DummyAuthenticator('chris_id1')
        plugin1.classifications = {IAuthenticator:['nomatch']}
        plugin2 = DummyAuthenticator('chris_id2')
        plugin2.classifications = {IAuthenticator:['match']}
        plugins = [ ('auth1', plugin1), ('auth2', plugin2) ]
        mw = self._makeOne(authenticators = plugins)
        identities = [ (None, {'login':'chris', 'password':'password'}) ]
        results = mw.authenticate(environ, 'match', identities)
        self.assertEqual(len(results), 1)
        result = results[0]
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0, 0))
        self.assertEqual(authenticator, plugin2)
        self.assertEqual(identifier, None)
        self.assertEqual(creds['login'], 'chris')
        self.assertEqual(creds['password'], 'password')
        self.assertEqual(userid, 'chris_id2')

    def test_challenge_noidentifier_noapp(self):
        environ = self._makeEnviron()
        challenger = DummyChallenger()
        plugins = [ ('challenge', challenger) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        app = mw.challenge(environ, 'match', '401 Unauthorized',
                           [], None, identity)
        self.assertEqual(app, None)
        self.assertEqual(environ['challenged'], app)

    def test_authenticate_success_multiresult_one_preauthenticated(self):
        environ = self._makeEnviron()
        mw = self._makeOne()
        preauth = DummyIdentifier({'repoze.pam.userid':'preauthenticated'})
        plugin1 = DummyAuthenticator('chris_id1')
        plugin2 = DummyAuthenticator('chris_id2')
        plugins = [ ('dummy1',plugin1), ('dummy2',plugin2) ]
        mw = self._makeOne(authenticators=plugins)
        creds = {'login':'chris', 'password':'password'}
        identities = [ (None, {'login':'chris', 'password':'password'}),
                       (preauth, preauth.credentials) ]
        results = mw.authenticate(environ, None, identities)
        self.assertEqual(len(results), 3)
        result = results[0]
        rank, authenticator, identifier, creds, userid = result
        self.assertEqual(rank, (0,0,))
        self.assertEqual(authenticator, None)
        self.assertEqual(identifier, preauth)
        self.assertEqual(creds['repoze.pam.userid'], 'preauthenticated')
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


    def test_challenge_noidentifier_withapp(self):
        environ = self._makeEnviron()
        app = DummyApp()
        challenger = DummyChallenger(app)
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
        identifier = DummyIdentifier()
        plugins = [ ('challenge', challenger) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = mw.challenge(environ, 'match', '401 Unauthorized',
                              [], identifier, identity)
        self.assertEqual(result, None)
        self.assertEqual(environ['challenged'], None)
        self.assertEqual(identifier.forgotten, identity)

    def test_challenge_identifier_app(self):
        environ = self._makeEnviron()
        app = DummyApp()
        challenger = DummyChallenger(app)
        identifier = DummyIdentifier()
        plugins = [ ('challenge', challenger) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = mw.challenge(environ, 'match', '401 Unauthorized',
                               [], identifier, identity)
        self.assertEqual(result, app)
        self.assertEqual(environ['challenged'], app)
        self.assertEqual(identifier.forgotten, identity)

    def test_multi_challenge_firstwins(self):
        environ = self._makeEnviron()
        app1 = DummyApp()
        app2 = DummyApp()
        challenger1 = DummyChallenger(app1)
        challenger2 = DummyChallenger(app2)
        identifier = DummyIdentifier()
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = mw.challenge(environ, 'match', '401 Unauthorized',
                              [], identifier, identity)
        self.assertEqual(result, app1)
        self.assertEqual(environ['challenged'], app1)
        self.assertEqual(identifier.forgotten, identity)

    def test_multi_challenge_skipnomatch_findimplicit(self):
        environ = self._makeEnviron()
        app1 = DummyApp()
        app2 = DummyApp()
        from repoze.pam.interfaces import IChallenger
        challenger1 = DummyChallenger(app1)
        challenger1.classifications = {IChallenger:['nomatch']}
        challenger2 = DummyChallenger(app2)
        challenger2.classifications = {IChallenger:None}
        identifier = DummyIdentifier()
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = mw.challenge(environ, 'match', '401 Unauthorized',
                               [], identifier, identity)
        self.assertEqual(result, app2)
        self.assertEqual(environ['challenged'], app2)
        self.assertEqual(identifier.forgotten, identity)

    def test_multi_challenge_skipnomatch_findexplicit(self):
        environ = self._makeEnviron()
        app1 = DummyApp()
        app2 = DummyApp()
        from repoze.pam.interfaces import IChallenger
        challenger1 = DummyChallenger(app1)
        challenger1.classifications = {IChallenger:['nomatch']}
        challenger2 = DummyChallenger(app2)
        challenger2.classifications = {IChallenger:['match']}
        identifier = DummyIdentifier()
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = mw.challenge(environ, 'match', '401 Unauthorized',
                               [], identifier, identity)
        self.assertEqual(result, app2)
        self.assertEqual(environ['challenged'], app2)
        self.assertEqual(identifier.forgotten, identity)

    def test_gather_metadata(self): 
        environ = self._makeEnviron()
        plugin1 = DummyMDProvider({'foo':'bar'})
        plugin2 = DummyMDProvider({'fuz':'baz'})
        plugins = [ ('meta1', plugin1), ('meta2', plugin2) ]
        mw = self._makeOne(mdproviders=plugins)
        classification = ''
        results = mw.gather_metadata(environ, classification, 'theman')
        self.assertEqual(results['foo'], 'bar')
        self.assertEqual(results['fuz'], 'baz')

    def test_gather_metadata_w_classification(self): 
        environ = self._makeEnviron()
        plugin1 = DummyMDProvider({'foo':'bar'})
        plugin2 = DummyMDProvider({'fuz':'baz'})
        from repoze.pam.interfaces import IMetadataProvider
        plugin2.classifications = {IMetadataProvider:['foo']}
        plugins = [ ('meta1', plugin1), ('meta2', plugin2) ]
        mw = self._makeOne(mdproviders=plugins)
        classification = 'monkey'
        results = mw.gather_metadata(environ, classification, 'theman')
        self.assertEqual(results['foo'], 'bar')
        self.assertEqual(results.get('fuz'), None)       

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
        identifier = DummyIdentifier()
        identifiers = [ ('identifier', identifier) ]
        mw = self._makeOne(app=app, identifiers=identifiers)
        start_response = DummyStartResponse()
        result = mw(environ, start_response)
        self.assertEqual(mw.app.environ, environ)
        self.assertEqual(result, ['body'])
        self.assertEqual(start_response.status, '200 OK')
        self.assertEqual(start_response.headers, headers)
        
    def test_call_401_no_identifiers(self):
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('401 Unauthorized', headers)
        from paste.httpexceptions import HTTPUnauthorized
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        mw = self._makeOne(app=app, challengers=challengers)
        start_response = DummyStartResponse()
        result = mw(environ, start_response)
        self.assertEqual(environ['challenged'], challenge_app)
        self.failUnless(result[0].startswith('401 Unauthorized\r\n'))

    def test_call_401_challenger_and_identifier_no_authenticator(self):
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('401 Unauthorized', headers)
        from paste.httpexceptions import HTTPUnauthorized
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        identifier = DummyIdentifier()
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
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('401 Unauthorized', headers)
        from paste.httpexceptions import HTTPUnauthorized
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        identifier = DummyIdentifier()
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
##         self.assertEqual(environ['repoze.pam.identity'], identifier.credentials)

    def test_call_200_challenger_and_identifier_and_authenticator(self):
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        from paste.httpexceptions import HTTPUnauthorized
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        identifier = DummyIdentifier()
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
##         self.assertEqual(environ['repoze.pam.identity'], identifier.credentials)


    def test_call_200_identity_reset(self):
        environ = self._makeEnviron()
        headers = [('a', '1')]
        new_identity = {'user_id':'foo', 'password':'bar'}
        app = DummyIdentityResetApp('200 OK', headers, new_identity)
        from paste.httpexceptions import HTTPUnauthorized
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        identifier = DummyIdentifier()
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
##         self.assertEqual(environ['repoze.pam.identity'], new_credentials)

    def test_call_200_with_metadata(self):
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        from paste.httpexceptions import HTTPUnauthorized
        challenge_app = HTTPUnauthorized()
        challenge = DummyChallenger(challenge_app)
        challengers = [ ('challenge', challenge) ]
        identifier = DummyIdentifier()
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
        self.assertEqual(environ['repoze.pam.identity']['repoze.pam.metadata'], {'foo':'bar'})

    # XXX need more call tests:
    #  - auth_id sorting

class TestMatchClassification(unittest.TestCase):
    def _getFUT(self):
        from repoze.pam.middleware import match_classification
        return match_classification

    def test_match_classification(self):
        f = self._getFUT()
        from repoze.pam.interfaces import IIdentifier
        from repoze.pam.interfaces import IChallenger
        from repoze.pam.interfaces import IAuthenticator
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
        plugin = self._makeOne()
        environ = self._makeFormEnviron(do_login=True, login='chris',
                                        password='password')
        result = plugin.identify(environ)
        self.assertEqual(result, {'login':'chris', 'password':'password'})

    def test_remember(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        identity = {}
        result = plugin.remember(environ, identity)
        self.assertEqual(result, None)
        self.assertEqual(environ['repoze.pam.plugins']['cookie'].remembered,
                         identity)

    def test_forget(self):
        plugin = self._makeOne()
        environ = self._makeFormEnviron()
        identity = {}
        result = plugin.forget(environ, identity)
        self.assertEqual(result, None)
        self.assertEqual(environ['repoze.pam.plugins']['cookie'].forgotten,
                         identity
                         )

    def test_challenge_defaultform(self):
        from repoze.pam.plugins.form import _DEFAULT_FORM
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

    def test_factory_withform(self):
        from repoze.pam.plugins.form import make_plugin
        here = os.path.dirname(__file__)
        fixtures = os.path.join(here, 'fixtures')
        form = os.path.join(fixtures, 'form.html')
        formbody = open(form).read()
        plugin = make_plugin(None, '__login', 'cookie', form)
        self.assertEqual(plugin.login_form_qs, '__login')
        self.assertEqual(plugin.rememberer_name, 'cookie')
        self.assertEqual(plugin.formbody, formbody)

    def test_factory_defaultform(self):
        from repoze.pam.plugins.form import make_plugin
        plugin = make_plugin(None, '__login', 'cookie')
        self.assertEqual(plugin.login_form_qs, '__login')
        self.assertEqual(plugin.rememberer_name, 'cookie')
        self.assertEqual(plugin.formbody, None)

class TestAuthTktCookiePlugin(Base):
    def _getTargetClass(self):
        from repoze.pam.plugins.auth_tkt import AuthTktCookiePlugin
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
        from repoze.pam.interfaces import IIdentifier
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
        self.assertEqual(result['repoze.pam.userid'], 'userid')
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
        self.assertEqual(result['repoze.pam.userid'], 'userid')
        self.assertEqual(result['userdata'], 'userdata')
        self.failUnless('timestamp' in result)
        self.assertEqual(environ['REMOTE_USER_TOKENS'], [''])
        self.assertEqual(environ['REMOTE_USER_DATA'],'userdata')
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
        result = plugin.remember(environ, {'repoze.pam.userid':'userid',
                                           'userdata':'userdata'})
        self.assertEqual(result, None)

    def test_remember_creds_different(self):
        plugin = self._makeOne('secret')
        old_val = self._makeTicket(userid='userid')
        environ = self._makeEnviron({'HTTP_COOKIE':'auth_tkt=%s' % old_val})
        new_val = self._makeTicket(userid='other', userdata='userdata')
        result = plugin.remember(environ, {'repoze.pam.userid':'other',
                                           'userdata':'userdata'})
        expected = 'auth_tkt=%s; Path=/;' % new_val
        self.assertEqual(result, [('Set-Cookie', expected)])

    def test_forget(self):
        plugin = self._makeOne('secret')
        environ = self._makeEnviron()
        headers = plugin.forget(environ, None)
        self.assertEqual(len(headers), 3)
        header = headers[0]
        name, value = header
        self.assertEqual(name, 'Set-Cookie')
        self.assertEqual(value, 'auth_tkt=""; Path=/')
        header = headers[1]
        name, value = header
        self.assertEqual(name, 'Set-Cookie')
        self.assertEqual(value, 'auth_tkt=""; Path=/; Domain=localhost')
        header = headers[2]
        name, value = header
        self.assertEqual(name, 'Set-Cookie')
        self.assertEqual(value, 'auth_tkt=""; Path=/; Domain=.localhost')

    def test_factory(self):
        from repoze.pam.plugins.auth_tkt import make_plugin
        plugin = make_plugin(None, 'secret')
        self.assertEqual(plugin.cookie_name, 'auth_tkt')
        self.assertEqual(plugin.secret, 'secret')
        self.assertEqual(plugin.include_ip, False)
        self.assertEqual(plugin.secure, False)

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
        iface_reg, name_reg = fn([], [], [], [])
        self.assertEqual(iface_reg, {})
        self.assertEqual(name_reg, {})
        
    def test_brokenimpl(self):
        fn = self._getFUT()
        self.assertRaises(ValueError, fn, [(None, DummyApp())], [], [], [])

    def test_ok(self):
        fn = self._getFUT()
        dummy_id1 = DummyIdentifier()
        dummy_id2 = DummyIdentifier()
        identifiers = [ ('id1', dummy_id1), ('id2', dummy_id2) ]
        dummy_auth = DummyAuthenticator(None)
        authenticators = [ ('auth', dummy_auth) ]
        dummy_challenger = DummyChallenger(None)
        challengers = [ ('challenger', dummy_challenger) ]
        dummy_mdprovider = DummyMDProvider()
        mdproviders = [ ('mdproviders', dummy_mdprovider) ]
        iface_reg, name_reg = fn(identifiers, authenticators, challengers, mdproviders)
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

class TestSQLAuthenticatorPlugin(unittest.TestCase):
    def _makeEnviron(self, kw=None):
        environ = {}
        environ['wsgi.version'] = (1,0)
        if kw is not None:
            environ.update(kw)
        return environ

    def _getTargetClass(self):
        from repoze.pam.plugins.sql import SQLAuthenticatorPlugin
        return SQLAuthenticatorPlugin

    def _makeOne(self, dsn, statement, compare_fn, cfactory):
        plugin = self._getTargetClass()(dsn, statement, compare_fn, cfactory)
        return plugin

    def _makeConnectionFactory(self, result):
        cursor = DummyCursor(result)
        def connect(dsn):
            conn = DummyConnection(dsn, cursor)
            return conn
        return connect
    
    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.pam.interfaces import IAuthenticator
        klass = self._getTargetClass()
        verifyClass(IAuthenticator, klass)

    def test_authenticate_noresults(self):
        conn_factory = self._makeConnectionFactory(())
        plugin = self._makeOne('dsn', 'statement', compare_fail, conn_factory)
        environ = self._makeEnviron()
        identity = {'login':'foo', 'password':'bar'}
        result = plugin.authenticate(environ, identity)
        self.assertEqual(result, None)
        self.assertEqual(plugin.conn.dsn, 'dsn')
        self.assertEqual(plugin.conn.curs.statement, 'statement')
        self.assertEqual(plugin.conn.curs.bindargs, identity)
        self.assertEqual(plugin.conn.curs.closed, True)

    def test_authenticate_comparefail(self):
        conn_factory = self._makeConnectionFactory(('user_id', 'password'))
        plugin = self._makeOne('dsn', 'statement', compare_fail, conn_factory)
        environ = self._makeEnviron()
        identity = {'login':'user_id', 'password':'bar'}
        result = plugin.authenticate(environ, identity)
        self.assertEqual(result, None)
        self.assertEqual(plugin.conn.dsn, 'dsn')
        self.assertEqual(plugin.conn.curs.statement, 'statement')
        self.assertEqual(plugin.conn.curs.bindargs, identity)
        self.assertEqual(plugin.conn.curs.closed, True)

    def test_authenticate_comparesuccess(self):
        conn_factory = self._makeConnectionFactory(('userid', 'password'))
        plugin = self._makeOne('dsn', 'statement', compare_success,
                               conn_factory)
        environ = self._makeEnviron()
        identity = {'login':'foo', 'password':'bar'}
        result = plugin.authenticate(environ, identity)
        self.assertEqual(result, 'userid')
        self.assertEqual(plugin.conn.dsn, 'dsn')
        self.assertEqual(plugin.conn.curs.statement, 'statement')
        self.assertEqual(plugin.conn.curs.bindargs, identity)
        self.assertEqual(plugin.conn.curs.closed, True)

    def test_authenticate_nologin(self):
        conn_factory = self._makeConnectionFactory(('userid', 'password'))
        plugin = self._makeOne('dsn', 'statement', compare_success,
                               conn_factory)
        environ = self._makeEnviron()
        identity = {}
        result = plugin.authenticate(environ, identity)
        self.assertEqual(result, None)

class TestDefaultPasswordCompare(unittest.TestCase):
    def _getFUT(self):
        from repoze.pam.plugins.sql import default_password_compare
        return default_password_compare

    def test_shaprefix_success(self):
        import sha
        stored = sha.new('password').hexdigest()
        stored = '{SHA}' + stored
        compare = self._getFUT()
        result = compare('password', stored)
        self.assertEqual(result, True)

    def test_shaprefix_fail(self):
        import sha
        stored = sha.new('password').hexdigest()
        stored = '{SHA}' + stored
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

class TestMakeSQLAuthenticatorPlugin(unittest.TestCase):
    def _getFUT(self):
        from repoze.pam.plugins.sql import make_plugin
        return make_plugin

    def test_nodsn(self):
        f = self._getFUT()
        self.assertRaises(ValueError, f, None, None, 'statement')

    def test_nostatement(self):
        f = self._getFUT()
        self.assertRaises(ValueError, f, None, 'dsn', None)

    def test_comparefunc_specd(self):
        f = self._getFUT()
        plugin = f(None, 'dsn', 'statement',
                   'repoze.pam.plugins.sql:make_plugin')
        self.assertEqual(plugin.dsn, 'dsn')
        self.assertEqual(plugin.statement, 'statement')
        self.assertEqual(plugin.compare_fn, f)

    def test_connfactory_specd(self):
        f = self._getFUT()
        plugin = f(None, 'dsn', 'statement', None,
                   'repoze.pam.plugins.sql:make_plugin')
        self.assertEqual(plugin.dsn, 'dsn')
        self.assertEqual(plugin.statement, 'statement')
        self.assertEqual(plugin.conn_factory, f)

    def test_onlydsnandstatement(self):
        f = self._getFUT()
        plugin = f(None, 'dsn', 'statement')
        self.assertEqual(plugin.dsn, 'dsn')
        self.assertEqual(plugin.statement, 'statement')
        from repoze.pam.plugins.sql import psycopg_connect
        from repoze.pam.plugins.sql import default_password_compare
        self.assertEqual(plugin.conn_factory, psycopg_connect)
        self.assertEqual(plugin.compare_fn, default_password_compare)

class TestIdentityDict(unittest.TestCase):
    def _getTargetClass(self):
        from repoze.pam.middleware import Identity
        return Identity

    def _makeOne(self, **kw):
        klass = self._getTargetClass()
        return klass(**kw)

    def test_str(self):
        identity = self._makeOne(foo=1)
        self.failUnless(str(identity).startswith('<repoze.pam identity'))
        self.assertEqual(identity['foo'], 1)

    def test_repr(self):
        identity = self._makeOne(foo=1)
        self.failUnless(str(identity).startswith('<repoze.pam identity'))
        self.assertEqual(identity['foo'], 1)

def compare_success(*arg):
    return True

def compare_fail(*arg):
    return False

class DummyCursor:
    def __init__(self, result):
        self.result = result
        self.statement = None
        self.bindargs = None
        self.closed = False

    def execute(self, statement, bindargs):
        self.statement = statement
        self.bindargs = bindargs

    def close(self):
        self.closed = True

    def fetchone(self):
        return self.result

class DummyConnection:
    def __init__(self, dsn, cursor):
        self.dsn = dsn
        self.curs = cursor

    def cursor(self):
        return self.curs


# XXX need make_middleware tests

class DummyApp:
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
        environ['repoze.pam.identity']['login'] = 'fred'
        environ['repoze.pam.identity']['password'] = 'schooled'
        start_response(self.status, self.headers)
        return ['body']
    
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
        self.forgotten = identity

    def remember(self, environ, identity):
        self.remembered = identity

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
        
    def metadata(self, environ, userid):
        return self._metadata

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
