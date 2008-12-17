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
        from repoze.who.middleware import PluggableAuthenticationMiddleware
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
    
    def test_accepts_logger(self):
        import logging
        logger = logging.Logger('something')
        logger.setLevel(logging.INFO)
        mw = self._makeOne(log_stream=logger)
        self.assertEqual(logger, mw.logger)

    def test_identify_success(self):
        environ = self._makeEnviron()
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
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
        credentials = {'login':'chris', 'password':'password'}
        plugin2 = DummyIdentifier(credentials)
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
        from repoze.who.interfaces import IIdentifier
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
        from repoze.who.interfaces import IIdentifier
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
        from repoze.who.interfaces import IAuthenticator
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
        from repoze.who.interfaces import IAuthenticator
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

    def test_authenticate_user_null_but_not_none(self):
        environ = self._makeEnviron()
        plugin1 = DummyAuthenticator(0)
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
        self.assertEqual(userid, 0)

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
        preauth = DummyIdentifier({'repoze.who.userid':'preauthenticated'})
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
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
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
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
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
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
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
        from repoze.who.interfaces import IChallenger
        challenger1 = DummyChallenger(app1)
        challenger1.classifications = {IChallenger:['nomatch']}
        challenger2 = DummyChallenger(app2)
        challenger2.classifications = {IChallenger:None}
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
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
        from repoze.who.interfaces import IChallenger
        challenger1 = DummyChallenger(app1)
        challenger1.classifications = {IChallenger:['nomatch']}
        challenger2 = DummyChallenger(app2)
        challenger2.classifications = {IChallenger:['match']}
        credentials = {'login':'chris', 'password':'password'}
        identifier = DummyIdentifier(credentials)
        plugins = [ ('challenge1', challenger1), ('challenge2', challenger2) ]
        mw = self._makeOne(challengers = plugins)
        identity = {'login':'chris', 'password':'password'}
        result = mw.challenge(environ, 'match', '401 Unauthorized',
                               [], identifier, identity)
        self.assertEqual(result, app2)
        self.assertEqual(environ['challenged'], app2)
        self.assertEqual(identifier.forgotten, identity)

    def test_add_metadata(self): 
        environ = self._makeEnviron()
        plugin1 = DummyMDProvider({'foo':'bar'})
        plugin2 = DummyMDProvider({'fuz':'baz'})
        plugins = [ ('meta1', plugin1), ('meta2', plugin2) ]
        mw = self._makeOne(mdproviders=plugins)
        classification = ''
        identity = {}
        results = mw.add_metadata(environ, classification, identity)
        self.assertEqual(identity['foo'], 'bar')
        self.assertEqual(identity['fuz'], 'baz')

    def test_add_metadata_w_classification(self): 
        environ = self._makeEnviron()
        plugin1 = DummyMDProvider({'foo':'bar'})
        plugin2 = DummyMDProvider({'fuz':'baz'})
        from repoze.who.interfaces import IMetadataProvider
        plugin2.classifications = {IMetadataProvider:['foo']}
        plugins = [ ('meta1', plugin1), ('meta2', plugin2) ]
        mw = self._makeOne(mdproviders=plugins)
        classification = 'monkey'
        identity = {}
        mw.add_metadata(environ, classification, identity)
        self.assertEqual(identity['foo'], 'bar')
        self.assertEqual(identity.get('fuz'), None)       

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
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('401 Unauthorized', headers)
        from paste.httpexceptions import HTTPUnauthorized
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
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        from paste.httpexceptions import HTTPUnauthorized
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
        environ = self._makeEnviron()
        headers = [('a', '1')]
        new_identity = {'user_id':'foo', 'password':'bar'}
        app = DummyIdentityResetApp('200 OK', headers, new_identity)
        from paste.httpexceptions import HTTPUnauthorized
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
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        from paste.httpexceptions import HTTPUnauthorized
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
        environ = self._makeEnviron()
        headers = [('a', '1')]
        app = DummyWorkingApp('200 OK', headers)
        challengers = []
        credentials = {'login':'chris', 'password':'password'}
        from paste.httpexceptions import HTTPFound
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
        self.assertEqual(len(headers), 3)
        self.assertEqual(headers[0],
                         ('location', 'http://example.com/redirect'))
        self.assertEqual(headers[1],
                         ('content-type', 'text/plain; charset=utf8'))
        self.assertEqual(headers[2],
                         ('a', '1'))
        self.assertEqual(start_response.exc_info, None)
        self.failIf(environ.has_key('repoze.who.application'))

    # XXX need more call tests:
    #  - auth_id sorting

class TestMatchClassification(unittest.TestCase):
    def _getFUT(self):
        from repoze.who.middleware import match_classification
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
                 rememberer_name='cookie'):
        plugin = self._getTargetClass()(login_form_url, login_handler_path,
                                        logout_handler_path,
                                        rememberer_name)
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
                          'auth_tkt=%s; Path=/' % new_val))
        self.assertEqual(result[1],
                         ('Set-Cookie',
                           'auth_tkt=%s; Path=/; Domain=localhost' % new_val))
        self.assertEqual(result[2],
                         ('Set-Cookie',
                           'auth_tkt=%s; Path=/; Domain=.localhost' % new_val))

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
                          'auth_tkt=%s; Path=/' % new_val))

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
                          'auth_tkt=%s; Path=/' % new_val))

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
                          'auth_tkt=%s; Path=/' % new_val))

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
        from repoze.who.plugins.auth_tkt import make_plugin
        plugin = make_plugin('secret')
        self.assertEqual(plugin.cookie_name, 'auth_tkt')
        self.assertEqual(plugin.secret, 'secret')
        self.assertEqual(plugin.include_ip, False)
        self.assertEqual(plugin.secure, False)

class TestDefaultRequestClassifier(Base):
    def _getFUT(self):
        from repoze.who.classifiers import default_request_classifier
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
        from repoze.who.middleware import make_registries
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
        mdproviders = [ ('mdproviders', dummy_mdprovider) ]
        iface_reg, name_reg = fn(identifiers, authenticators, challengers,
                                 mdproviders)
        from repoze.who.interfaces import IIdentifier
        from repoze.who.interfaces import IAuthenticator
        from repoze.who.interfaces import IChallenger
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
                   'repoze.who.tests:make_dummy_connfactory',
                   None)
        self.assertEqual(plugin.query, 'statement')
        self.assertEqual(plugin.conn_factory, DummyConnFactory)
        from repoze.who.plugins.sql import default_password_compare
        self.assertEqual(plugin.compare_fn, default_password_compare)

    def test_comparefunc_specd(self):
        f = self._getFUT()
        plugin = f('statement',
                   'repoze.who.tests:make_dummy_connfactory',
                   'repoze.who.tests:make_dummy_connfactory')
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
                   'repoze.who.tests:make_dummy_connfactory', None)
        self.assertEqual(plugin.name, 'name')
        self.assertEqual(plugin.query, 'statement')
        self.assertEqual(plugin.conn_factory, DummyConnFactory)
        self.assertEqual(plugin.filter, None)

    def test_comparefn_specd(self):
        f = self._getFUT()
        plugin = f('name', 'statement',
                   'repoze.who.tests:make_dummy_connfactory',
                   'repoze.who.tests:make_dummy_connfactory')
        self.assertEqual(plugin.name, 'name')
        self.assertEqual(plugin.query, 'statement')
        self.assertEqual(plugin.conn_factory, DummyConnFactory)
        self.assertEqual(plugin.filter, make_dummy_connfactory)

class TestIdentityDict(unittest.TestCase):
    def _getTargetClass(self):
        from repoze.who.middleware import Identity
        return Identity

    def _makeOne(self, **kw):
        klass = self._getTargetClass()
        return klass(**kw)

    def test_str(self):
        identity = self._makeOne(foo=1)
        self.failUnless(str(identity).startswith('<repoze.who identity'))
        self.assertEqual(identity['foo'], 1)

    def test_repr(self):
        identity = self._makeOne(foo=1)
        self.failUnless(str(identity).startswith('<repoze.who identity'))
        self.assertEqual(identity['foo'], 1)

class TestWhoConfig(unittest.TestCase):

    def _getTargetClass(self):
        from repoze.who.config import WhoConfig
        return WhoConfig

    def _makeOne(self, here='/', *args, **kw):
        return self._getTargetClass()(here, *args, **kw)

    def _getDummyPluginClass(self, iface):
        from zope.interface import classImplements
        if not iface.implementedBy(DummyPlugin):
            classImplements(DummyPlugin, iface)
        return DummyPlugin

    def test_defaults_before_parse(self):
        config = self._makeOne()
        self.assertEqual(config.request_classifier, None)
        self.assertEqual(config.challenge_decider, None)
        self.assertEqual(config.remote_user_key, 'REMOTE_USER')
        self.assertEqual(len(config.plugins), 0)
        self.assertEqual(len(config.identifiers), 0)
        self.assertEqual(len(config.authenticators), 0)
        self.assertEqual(len(config.challengers), 0)
        self.assertEqual(len(config.mdproviders), 0)

    def test_parse_empty_string(self):
        config = self._makeOne()
        config.parse('')
        self.assertEqual(config.request_classifier, None)
        self.assertEqual(config.challenge_decider, None)
        self.assertEqual(config.remote_user_key, 'REMOTE_USER')
        self.assertEqual(len(config.plugins), 0)
        self.assertEqual(len(config.identifiers), 0)
        self.assertEqual(len(config.authenticators), 0)
        self.assertEqual(len(config.challengers), 0)
        self.assertEqual(len(config.mdproviders), 0)

    def test_parse_empty_file(self):
        from StringIO import StringIO
        config = self._makeOne()
        config.parse(StringIO())
        self.assertEqual(config.request_classifier, None)
        self.assertEqual(config.challenge_decider, None)
        self.assertEqual(config.remote_user_key, 'REMOTE_USER')
        self.assertEqual(len(config.plugins), 0)
        self.assertEqual(len(config.identifiers), 0)
        self.assertEqual(len(config.authenticators), 0)
        self.assertEqual(len(config.challengers), 0)
        self.assertEqual(len(config.mdproviders), 0)

    def test_parse_plugins(self):
        config = self._makeOne()
        config.parse(PLUGINS_ONLY)
        self.assertEqual(len(config.plugins), 2)
        self.failUnless(isinstance(config.plugins['foo'],
                                   DummyPlugin))
        bar = config.plugins['bar']
        self.failUnless(isinstance(bar, DummyPlugin))
        self.assertEqual(bar.credentials, 'qux')

    def test_parse_general_empty(self):
        config = self._makeOne()
        config.parse('[general]')
        self.assertEqual(config.request_classifier, None)
        self.assertEqual(config.challenge_decider, None)
        self.assertEqual(config.remote_user_key, 'REMOTE_USER')
        self.assertEqual(len(config.plugins), 0)

    def test_parse_general_only(self):
        from repoze.who.interfaces import IRequestClassifier
        from repoze.who.interfaces import IChallengeDecider
        class IDummy(IRequestClassifier, IChallengeDecider):
            pass
        PLUGIN_CLASS = self._getDummyPluginClass(IDummy)
        config = self._makeOne()
        config.parse(GENERAL_ONLY)
        self.failUnless(isinstance(config.request_classifier, PLUGIN_CLASS))
        self.failUnless(isinstance(config.challenge_decider, PLUGIN_CLASS))
        self.assertEqual(config.remote_user_key, 'ANOTHER_REMOTE_USER')
        self.assertEqual(len(config.plugins), 0)

    def test_parse_general_with_plugins(self):
        from repoze.who.interfaces import IRequestClassifier
        from repoze.who.interfaces import IChallengeDecider
        class IDummy(IRequestClassifier, IChallengeDecider):
            pass
        PLUGIN_CLASS = self._getDummyPluginClass(IDummy)
        config = self._makeOne()
        config.parse(GENERAL_WITH_PLUGINS)
        self.failUnless(isinstance(config.request_classifier, PLUGIN_CLASS))
        self.failUnless(isinstance(config.challenge_decider, PLUGIN_CLASS))

    def test_parse_identifiers_only(self):
        from repoze.who.interfaces import IIdentifier
        PLUGIN_CLASS = self._getDummyPluginClass(IIdentifier)
        config = self._makeOne()
        config.parse(IDENTIFIERS_ONLY)
        identifiers = config.identifiers
        self.assertEqual(len(identifiers), 2)
        first, second = identifiers
        self.assertEqual(first[0], 'repoze.who.tests:DummyPlugin')
        self.failUnless(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[IIdentifier], 'klass1')
        self.assertEqual(second[0], 'repoze.who.tests:DummyPlugin')
        self.failUnless(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_identifiers_with_plugins(self):
        from repoze.who.interfaces import IIdentifier
        PLUGIN_CLASS = self._getDummyPluginClass(IIdentifier)
        config = self._makeOne()
        config.parse(IDENTIFIERS_WITH_PLUGINS)
        identifiers = config.identifiers
        self.assertEqual(len(identifiers), 2)
        first, second = identifiers
        self.assertEqual(first[0], 'foo')
        self.failUnless(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[IIdentifier], 'klass1')
        self.assertEqual(second[0], 'bar')
        self.failUnless(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_authenticators_only(self):
        from repoze.who.interfaces import IAuthenticator
        PLUGIN_CLASS = self._getDummyPluginClass(IAuthenticator)
        config = self._makeOne()
        config.parse(AUTHENTICATORS_ONLY)
        authenticators = config.authenticators
        self.assertEqual(len(authenticators), 2)
        first, second = authenticators
        self.assertEqual(first[0], 'repoze.who.tests:DummyPlugin')
        self.failUnless(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[IAuthenticator], 'klass1')
        self.assertEqual(second[0], 'repoze.who.tests:DummyPlugin')
        self.failUnless(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_authenticators_with_plugins(self):
        from repoze.who.interfaces import IAuthenticator
        PLUGIN_CLASS = self._getDummyPluginClass(IAuthenticator)
        config = self._makeOne()
        config.parse(AUTHENTICATORS_WITH_PLUGINS)
        authenticators = config.authenticators
        self.assertEqual(len(authenticators), 2)
        first, second = authenticators
        self.assertEqual(first[0], 'foo')
        self.failUnless(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[IAuthenticator], 'klass1')
        self.assertEqual(second[0], 'bar')
        self.failUnless(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_challengers_only(self):
        from repoze.who.interfaces import IChallenger
        PLUGIN_CLASS = self._getDummyPluginClass(IChallenger)
        config = self._makeOne()
        config.parse(CHALLENGERS_ONLY)
        challengers = config.challengers
        self.assertEqual(len(challengers), 2)
        first, second = challengers
        self.assertEqual(first[0], 'repoze.who.tests:DummyPlugin')
        self.failUnless(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[IChallenger], 'klass1')
        self.assertEqual(second[0], 'repoze.who.tests:DummyPlugin')
        self.failUnless(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_challengers_with_plugins(self):
        from repoze.who.interfaces import IChallenger
        PLUGIN_CLASS = self._getDummyPluginClass(IChallenger)
        config = self._makeOne()
        config.parse(CHALLENGERS_WITH_PLUGINS)
        challengers = config.challengers
        self.assertEqual(len(challengers), 2)
        first, second = challengers
        self.assertEqual(first[0], 'foo')
        self.failUnless(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[IChallenger], 'klass1')
        self.assertEqual(second[0], 'bar')
        self.failUnless(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_mdproviders_only(self):
        from repoze.who.interfaces import IMetadataProvider
        PLUGIN_CLASS = self._getDummyPluginClass(IMetadataProvider)
        config = self._makeOne()
        config.parse(MDPROVIDERS_ONLY)
        mdproviders = config.mdproviders
        self.assertEqual(len(mdproviders), 2)
        first, second = mdproviders
        self.assertEqual(first[0], 'repoze.who.tests:DummyPlugin')
        self.failUnless(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[IMetadataProvider], 'klass1')
        self.assertEqual(second[0], 'repoze.who.tests:DummyPlugin')
        self.failUnless(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_mdproviders_with_plugins(self):
        from repoze.who.interfaces import IMetadataProvider
        PLUGIN_CLASS = self._getDummyPluginClass(IMetadataProvider)
        config = self._makeOne()
        config.parse(MDPROVIDERS_WITH_PLUGINS)
        mdproviders = config.mdproviders
        self.assertEqual(len(mdproviders), 2)
        first, second = mdproviders
        self.assertEqual(first[0], 'foo')
        self.failUnless(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[IMetadataProvider], 'klass1')
        self.assertEqual(second[0], 'bar')
        self.failUnless(isinstance(second[1], PLUGIN_CLASS))

class DummyPlugin:
    def __init__(self, **kw):
        self.__dict__.update(kw)

PLUGINS_ONLY = """\
[plugin:foo]
use = repoze.who.tests:DummyPlugin

[plugin:bar]
use = repoze.who.tests:DummyPlugin
credentials = qux
"""

GENERAL_ONLY = """\
[general]
request_classifier = repoze.who.tests:DummyPlugin
challenge_decider = repoze.who.tests:DummyPlugin
remote_user_key = ANOTHER_REMOTE_USER
"""

GENERAL_WITH_PLUGINS = """\
[general]
request_classifier = classifier
challenge_decider = decider

[plugin:classifier]
use = repoze.who.tests:DummyPlugin

[plugin:decider]
use = repoze.who.tests:DummyPlugin
"""

IDENTIFIERS_ONLY = """\
[identifiers]
plugins = 
    repoze.who.tests:DummyPlugin;klass1
    repoze.who.tests:DummyPlugin
"""

IDENTIFIERS_WITH_PLUGINS = """\
[identifiers]
plugins = 
    foo;klass1
    bar

[plugin:foo]
use = repoze.who.tests:DummyPlugin

[plugin:bar]
use = repoze.who.tests:DummyPlugin
"""

AUTHENTICATORS_ONLY = """\
[authenticators]
plugins = 
    repoze.who.tests:DummyPlugin;klass1
    repoze.who.tests:DummyPlugin
"""

AUTHENTICATORS_WITH_PLUGINS = """\
[authenticators]
plugins = 
    foo;klass1
    bar

[plugin:foo]
use = repoze.who.tests:DummyPlugin

[plugin:bar]
use = repoze.who.tests:DummyPlugin
"""

CHALLENGERS_ONLY = """\
[challengers]
plugins = 
    repoze.who.tests:DummyPlugin;klass1
    repoze.who.tests:DummyPlugin
"""

CHALLENGERS_WITH_PLUGINS = """\
[challengers]
plugins = 
    foo;klass1
    bar

[plugin:foo]
use = repoze.who.tests:DummyPlugin

[plugin:bar]
use = repoze.who.tests:DummyPlugin
"""

MDPROVIDERS_ONLY = """\
[mdproviders]
plugins = 
    repoze.who.tests:DummyPlugin;klass1
    repoze.who.tests:DummyPlugin
"""

MDPROVIDERS_WITH_PLUGINS = """\
[mdproviders]
plugins = 
    foo;klass1
    bar

[plugin:foo]
use = repoze.who.tests:DummyPlugin

[plugin:bar]
use = repoze.who.tests:DummyPlugin
"""

class TestConfigMiddleware(unittest.TestCase):
    tempfile = None

    def setUp(self):
        pass

    def tearDown(self):
        if self.tempfile is not None:
            self.tempfile.close()

    def _getFactory(self):
        from repoze.who.config import make_middleware_with_config
        return make_middleware_with_config

    def _getTempfile(self, text):
        import tempfile
        tf = self.tempfile = tempfile.NamedTemporaryFile()
        tf.write(text)
        tf.flush()
        return tf

    def test_sample_config(self):
        app = DummyApp()
        factory = self._getFactory()
        tempfile = self._getTempfile(SAMPLE_CONFIG)
        global_cohf = {'here': '/'}
        middleware = factory(app, global_cohf, config_file=tempfile.name,
                             log_file='STDOUT', log_level='debug')
        from repoze.who.interfaces import IIdentifier
        from repoze.who.interfaces import IAuthenticator
        from repoze.who.interfaces import IChallenger
        self.assertEqual(len(middleware.registry[IIdentifier]), 3)
        self.assertEqual(len(middleware.registry[IAuthenticator]), 1)
        self.assertEqual(len(middleware.registry[IChallenger]), 2)
        self.failUnless(middleware.logger, middleware.logger)
        import logging
        self.assertEqual(middleware.logger.getEffectiveLevel(), logging.DEBUG)

SAMPLE_CONFIG = """\
[plugin:form]
use = repoze.who.plugins.form:make_plugin
login_form_qs = __do_login
rememberer_name = auth_tkt

[plugin:auth_tkt]
use = repoze.who.plugins.auth_tkt:make_plugin
secret = s33kr1t
cookie_name = oatmeal
secure = False
include_ip = True

[plugin:basicauth]
use = repoze.who.plugins.basicauth:make_plugin
realm = 'sample'

[plugin:htpasswd]
use = repoze.who.plugins.htpasswd:make_plugin
filename = %(here)s/etc/passwd
check_fn = repoze.who.plugins.htpasswd:crypt_check

[general]
request_classifier = repoze.who.classifiers:default_request_classifier
challenge_decider = repoze.who.classifiers:default_challenge_decider

[identifiers]
plugins = 
    form;browser
    auth_tkt
    basicauth

[authenticators]
plugins = htpasswd

[challengers]
plugins =
    form;browser
    basicauth

[mdproviders]
plugins =

"""

class AuthenticatedPredicateTests(unittest.TestCase):

    def _getFUT(self):
        from repoze.who.restrict import authenticated_predicate
        return authenticated_predicate()

    def test___call___no_identity_returns_False(self):
        predicate = self._getFUT()
        environ = {}
        self.failIf(predicate(environ))

    def test___call___w_REMOTE_AUTH_returns_True(self):
        predicate = self._getFUT()
        environ = {'REMOTE_USER': 'fred'}
        self.failUnless(predicate(environ))

    def test___call___w_repoze_who_identity_returns_True(self):
        predicate = self._getFUT()
        environ = {'repoze.who.identity': {'login': 'fred'}}
        self.failUnless(predicate(environ))

class PredicateRestrictionTests(unittest.TestCase):

    def _getTargetClass(self):
        from repoze.who.restrict import PredicateRestriction
        return PredicateRestriction

    def _makeOne(self, app=None, **kw):
        if app is None:
            app = DummyApp()
        return self._getTargetClass()(app, **kw)

    def test___call___disabled_predicate_false_calls_app_not_predicate(self):
        _tested = []
        def _factory():
            def _predicate(env):
                _tested.append(env)
                return False
            return _predicate

        _started = []
        def _start_response(status, headers):
            _started.append((status, headers))
        environ = {'testing': True}

        restrict = self._makeOne(predicate=_factory, enabled=False)
        restrict(environ, _start_response)

        self.assertEqual(len(_tested), 0)
        self.assertEqual(len(_started), 0)
        self.assertEqual(restrict.app.environ, environ)

    def test___call___enabled_predicate_false_returns_401(self):
        _tested = []
        def _factory():
            def _predicate(env):
                _tested.append(env)
                return False
            return _predicate

        _started = []
        def _start_response(status, headers):
            _started.append((status, headers))
        environ = {'testing': True}

        restrict = self._makeOne(predicate=_factory)
        restrict(environ, _start_response)

        self.assertEqual(len(_tested), 1)
        self.assertEqual(len(_started), 1, _started)
        self.assertEqual(_started[0][0], '401 Unauthorized')
        self.assertEqual(restrict.app.environ, None)

    def test___call___enabled_predicate_true_calls_app(self):
        _tested = []
        def _factory():
            def _predicate(env):
                _tested.append(env)
                return True
            return _predicate

        _started = []
        def _start_response(status, headers):
            _started.append((status, headers))
        environ = {'testing': True, 'REMOTE_USER': 'fred'}

        restrict = self._makeOne(predicate=_factory)
        restrict(environ, _start_response)

        self.assertEqual(len(_tested), 1)
        self.assertEqual(len(_started), 0)
        self.assertEqual(restrict.app.environ, environ)

class MakePredicateRestrictionTests(unittest.TestCase):

    def _getFUT(self):
        from repoze.who.restrict import make_predicate_restriction
        return make_predicate_restriction

    def test_non_string_predicate_no_args(self):
        fut = self._getFUT()
        app = DummyApp()
        def _predicate(env):
            return True
        def _factory():
            return _predicate

        filter = fut(app, {}, predicate=_factory)

        self.failUnless(filter.app is app)
        self.failUnless(filter.predicate is _predicate)
        self.failUnless(filter.enabled)

    def test_disabled_non_string_predicate_w_args(self):
        fut = self._getFUT()
        app = DummyApp()

        filter = fut(app, {}, predicate=DummyPredicate, enabled=False,
                     foo='Foo')

        self.failUnless(filter.app is app)
        self.failUnless(isinstance(filter.predicate, DummyPredicate))
        self.assertEqual(filter.predicate.foo, 'Foo')
        self.failIf(filter.enabled)

    def test_enabled_string_predicate_w_args(self):
        fut = self._getFUT()
        app = DummyApp()

        filter = fut(app, {}, predicate='repoze.who.tests:DummyPredicate',
                     enabled=True, foo='Foo')

        self.failUnless(filter.app is app)
        self.failUnless(isinstance(filter.predicate, DummyPredicate))
        self.assertEqual(filter.predicate.foo, 'Foo')
        self.failUnless(filter.enabled)

class DummyPredicate:
    def __init__(self, **kw):
        self.__dict__.update(kw)
    def __call__(self, env):
        return True

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
