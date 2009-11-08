from zope.interface import implements

from repoze.who.interfaces import IAPIFactory
from repoze.who.interfaces import IIdentifier
from repoze.who.interfaces import IAuthenticator
from repoze.who.interfaces import IChallenger
from repoze.who.interfaces import IMetadataProvider


def get_api(environ):
    return environ.get('repoze.who.api')


class APIFactory(object):
    implements(IAPIFactory)

    def __init__(self,
                 identifiers=(),
                 authenticators=(),
                 challengers=(),
                 mdproviders=(),
                 request_classifier=None,
                 challenge_decider=None,
                 logger=None,
                ):
        self.identifiers = identifiers
        self.authenticators = authenticators
        self.challengers = challengers
        self.mdproviders = mdproviders
        self.request_classifier = request_classifier
        self.challenge_decider = challenge_decider
        self.logger = logger

    def __call__(self, environ):
        """ See IAPIFactory.
        """
        api = environ.get('repoze.who.api')
        if api is None:
            api = environ['repoze.who.api'] = API(self.identifiers,
                                                  self.authenticators,
                                                  self.challengers,
                                                  self.mdproviders,
                                                  self.request_classifier,
                                                  self.challenge_decider,
                                                  self.logger,
                                                 )
        return api


def verify(plugin, iface):
    from zope.interface.verify import verifyObject
    verifyObject(iface, plugin, tentative=True)

 
def make_registries(identifiers, authenticators, challengers, mdproviders):
    from zope.interface.verify import BrokenImplementation
    interface_registry = {}
    name_registry = {}

    for supplied, iface in [ (identifiers, IIdentifier),
                             (authenticators, IAuthenticator),
                             (challengers, IChallenger),
                             (mdproviders, IMetadataProvider)]:

        for name, value in supplied:
            try:
                verify(value, iface)
            except BrokenImplementation, why:
                why = str(why)
                raise ValueError(str(name) + ': ' + why)
            L = interface_registry.setdefault(iface, [])
            L.append(value)
            name_registry[name] = value

    return interface_registry, name_registry


def match_classification(iface, plugins, classification):
    result = []
    for plugin in plugins:
        
        plugin_classifications = getattr(plugin, 'classifications', {})
        iface_classifications = plugin_classifications.get(iface)
        if not iface_classifications: # good for any
            result.append(plugin)
            continue
        if classification in iface_classifications:
            result.append(plugin)

    return result


class API(object):

    def __init__(self,
                 identifiers,
                 authenticators,
                 challengers,
                 mdproviders,
                 request_classifier,
                 challenge_decider,
                 logger,
                ):
        (self.interface_registry,
         self.name_registry) = make_registries(identifiers, authenticators,
                                               challengers, mdproviders)
        self.authenticators = authenticators
        self.challengers = challengers
        self.mdproviders = mdproviders
        self.request_classifier = request_classifier
        self.challenge_decider = challenge_decider
        self.logger = logger

    def identify(self, environ, classification):
        logger = self.logger
        candidates = self.interface_registry.get(IIdentifier, ())
        logger and self.logger.info('identifier plugins registered %s' %
                                    (candidates,))
        plugins = match_classification(IIdentifier, candidates, classification)
        logger and self.logger.info(
            'identifier plugins matched for '
            'classification "%s": %s' % (classification, plugins))

        results = []
        for plugin in plugins:
            identity = plugin.identify(environ)
            if identity is not None:
                logger and logger.debug(
                    'identity returned from %s: %s' % (plugin, identity))
                results.append((plugin, identity))
            else:
                logger and logger.debug(
                    'no identity returned from %s (%s)' % (plugin, identity))

        logger and logger.debug('identities found: %s' % (results,))
        return results

    def authenticate(self, environ, classification, identities):
        logger = self.logger
        candidates = self.interface_registry.get(IAuthenticator, [])
        logger and self.logger.info('authenticator plugins registered %s' %
                                    candidates)
        plugins = match_classification(IAuthenticator, candidates,
                                       classification)
        logger and self.logger.info(
            'authenticator plugins matched for '
            'classification "%s": %s' % (classification, plugins))

        # 'preauthenticated' identities are considered best-ranking
        identities, results, id_rank_start = self._filter_preauthenticated(
            identities)

        auth_rank = 0

        for plugin in plugins:
            identifier_rank = id_rank_start
            for identifier, identity in identities:
                userid = plugin.authenticate(environ, identity)
                if userid is not None:
                    logger and logger.debug(
                        'userid returned from %s: "%s"' % (plugin, userid))

                    # stamp the identity with the userid
                    identity['repoze.who.userid'] = userid
                    rank = (auth_rank, identifier_rank)
                    results.append(
                        (rank, plugin, identifier, identity, userid)
                        )
                else:
                    logger and logger.debug(
                        'no userid returned from %s: (%s)' % (
                        plugin, userid))
                identifier_rank += 1
            auth_rank += 1

        logger and logger.debug('identities authenticated: %s' % (results,))
        return results

    def _filter_preauthenticated(self, identities):
        logger = self.logger
        results = []
        new_identities = identities[:]

        identifier_rank = 0
        for thing in identities:
            identifier, identity = thing
            userid = identity.get('repoze.who.userid')
            if userid is not None:
                # the identifier plugin has already authenticated this
                # user (domain auth, auth ticket, etc)
                logger and logger.info(
                  'userid preauthenticated by %s: "%s" '
                  '(repoze.who.userid set)' % (identifier, userid)
                  )
                rank = (0, identifier_rank)
                results.append(
                    (rank, None, identifier, identity, userid)
                    )
                identifier_rank += 1
                new_identities.remove(thing)
        return new_identities, results, identifier_rank

    def add_metadata(self, environ, classification, identity):
        candidates = self.interface_registry.get(IMetadataProvider, ())
        plugins = match_classification(IMetadataProvider, candidates,
                                       classification)        
        for plugin in plugins:
            plugin.add_metadata(environ, identity)

    def challenge(self, environ, classification, status, app_headers,
                  identifier, identity):
        # happens on egress
        logger = self.logger

        forget_headers = []

        if identifier:
            forget_headers = identifier.forget(environ, identity)
            if forget_headers is None:
                forget_headers = []
            else:
                logger and logger.info('forgetting via headers from %s: %s'
                                       % (identifier, forget_headers))

        candidates = self.interface_registry.get(IChallenger, ())
        logger and logger.info('challengers registered: %s' % candidates)
        plugins = match_classification(IChallenger,
                                       candidates, classification)
        logger and logger.info('challengers matched for '
                               'classification "%s": %s' % (classification,
                                                            plugins))
        for plugin in plugins:
            app = plugin.challenge(environ, status, app_headers,
                                   forget_headers)
            if app is not None:
                # new WSGI application
                logger and logger.info(
                    'challenger plugin %s "challenge" returned an app' % (
                    plugin))
                return app

        # signifies no challenge
        logger and logger.info('no challenge app returned')
        return None
