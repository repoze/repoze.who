import logging
from StringIO import StringIO
import sys

from repoze.pam.interfaces import IIdentifier
from repoze.pam.interfaces import IAuthenticator
from repoze.pam.interfaces import IChallenger
from repoze.pam.interfaces import IMetadataProvider

_STARTED = '-- repoze.pam request started --'
_ENDED = '-- repoze.pam request ended --'

class PluggableAuthenticationMiddleware(object):
    def __init__(self, app,
                 identifiers,
                 authenticators,
                 challengers,
                 mdproviders,
                 classifier,
                 challenge_decider,
                 log_stream = None,
                 log_level = logging.INFO,
                 remote_user_key = 'REMOTE_USER',
                 ):
        iregistry, nregistry = make_registries(identifiers, authenticators,
                                               challengers, mdproviders)
        self.registry = iregistry
        self.name_registry = nregistry
        self.app = app
        self.classifier = classifier
        self.challenge_decider = challenge_decider
        self.remote_user_key = remote_user_key
        self.logger = None
        if log_stream:
            handler = logging.StreamHandler(log_stream)
            fmt = '%(asctime)s %(message)s'
            formatter = logging.Formatter(fmt)
            handler.setFormatter(formatter)
            self.logger = logging.Logger('repoze.pam')
            self.logger.addHandler(handler)
            self.logger.setLevel(log_level)

    def __call__(self, environ, start_response):
        if self.remote_user_key in environ:
            # act as a pass through if REMOTE_USER (or whatever) is
            # already set
            return self.app(environ, start_response)

        environ['repoze.pam.plugins'] = self.name_registry
        environ['repoze.pam.logger'] = self.logger

        logger = self.logger
        logger and logger.info(_STARTED)
        classification = self.classifier(environ)
        logger and logger.info('request classification: %s' % classification)
        userid = None
        identity = None
        identifier = None

        ids = self.identify(environ, classification)
        # ids will be list of tuples: [ (IIdentifier, identity) ]
        if ids:
            auth_ids = self.authenticate(environ, classification, ids)

            # auth_ids will be a list of five-tuples in the form
            #  ( (auth_rank, id_rank), authenticator, identifier, identity,
            #    userid )
            #
            # When sorted, its first element will represent the "best"
            # identity for this request.

            if auth_ids:
                auth_ids.sort()
                best = auth_ids[0]
                rank, authenticator, identifier, identity, userid = best
                identity = Identity(identity) # dont show contents at print
                # add the identity to the environment; a downstream
                # application can mutate it to do an 'identity reset'
                # as necessary, e.g. identity['login'] = 'foo',
                # identity['password'] = 'bar'
                environ['repoze.pam.identity'] = identity
                metadata = self.gather_metadata(environ, userid)
                identity['repoze.pam.metadata'] = metadata
                # set the REMOTE_USER
                environ[self.remote_user_key] = userid
        else:
            logger and logger.info('no identities found, not authenticating')

        wrapper = StartResponseWrapper(start_response)
        app_iter = self.app(environ, wrapper.wrap_start_response)

        if self.challenge_decider(environ, wrapper.status, wrapper.headers):
            logger and logger.info('challenge required')

            challenge_app = self.challenge(
                environ,
                classification,
                wrapper.status,
                wrapper.headers,
                identifier,
                identity
                )
            if challenge_app is not None:
                logger and logger.info('executing challenge app')
                if app_iter:
                    list(app_iter) # unwind the original app iterator
                # replace the downstream app with the challenge app
                app_iter = challenge_app(environ, start_response)
            else:
                logger and logger.info('configuration error: no challengers')
                raise RuntimeError('no challengers found')
        else:
            logger and logger.info('no challenge required')
            remember_headers = []
            if identifier:
                remember_headers = identifier.remember(environ, identity)
                if remember_headers:
                    logger and logger.info('remembering via headers from %s: %s'
                                           % (identifier, remember_headers))
            wrapper.finish_response(remember_headers)

        logger and logger.info(_ENDED)
        return app_iter

    def identify(self, environ, classification):
        logger = self.logger
        candidates = self.registry.get(IIdentifier, ())
        logger and self.logger.info('identifier plugins registered %s' %
                                    candidates)
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

        logger and logger.debug('identities found: %s' % results)
        return results

    def gather_metadata(self, environ, userid):
        plugins = self.registry.get(IMetadataProvider, ())
        metadata = {}
        for plugin in plugins:
            data = plugin.metadata(environ, userid)
            if data:
                metadata.update(data)
        return metadata

    def authenticate(self, environ, classification, identities):
        logger = self.logger
        candidates = self.registry.get(IAuthenticator, ())
        logger and self.logger.info('authenticator plugins registered %s' %
                                    candidates)
        plugins = match_classification(IAuthenticator, candidates,
                                       classification)
        logger and self.logger.info(
            'authenticator plugins matched for '
            'classification "%s": %s' % (classification, plugins))

        # 'preauthenticated' identities are considered best-ranking
        identities, results, id_rank_start =self._filter_preauthenticated(
            identities)

        auth_rank = 0

        for plugin in plugins:
            identifier_rank = id_rank_start
            for identifier, identity in identities:
                userid = plugin.authenticate(environ, identity)
                if userid:
                    logger and logger.debug(
                        'userid returned from %s: "%s"' % (plugin, userid))

                    # stamp the identity with the userid
                    identity['repoze.pam.userid'] = userid
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

        logger and logger.debug('identities authenticated: %s' % results)
        return results

    def _filter_preauthenticated(self, identities):
        logger = self.logger
        results = []
        new_identities = identities[:]

        identifier_rank = 0
        for thing in identities:
            identifier, identity = thing
            userid = identity.get('repoze.pam.userid')
            if userid is not None:
                # the identifier plugin has already authenticated this
                # user (domain auth, auth ticket, etc)
                logger and logger.info(
                  'userid preauthenticated by %s: "%s" '
                  '(repoze.pam.userid set)' % (identifier, userid)
                  )
                rank = (0, identifier_rank)
                results.append(
                    (rank, None, identifier, identity, userid)
                    )
                identifier_rank += 1
                new_identities.remove(thing)
        return new_identities, results, identifier_rank

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

        candidates = self.registry.get(IChallenger, ())
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

class StartResponseWrapper(object):
    def __init__(self, start_response):
        self.start_response = start_response
        self.status = None
        self.headers = []
        self.exc_info = None
        self.buffer = StringIO()

    def wrap_start_response(self, status, headers, exc_info=None):
        self.headers = headers
        self.status = status
        self.exc_info = exc_info
        return self.buffer.write

    def finish_response(self, extra_headers):
        if not extra_headers:
            extra_headers = []
        headers = self.headers + extra_headers
        write = self.start_response(self.status, headers, self.exc_info)
        if write:
            self.buffer.seek(0)
            value = self.buffer.getvalue()
            if value:
                write(value)
            if hasattr(write, 'close'):
                write.close()

def make_middleware(app, global_conf, config_file=None):
    if config_file is None:
        raise ValueError('config_file must be specified')
    return PluggableAuthenticationMiddleware(app)

def make_test_middleware(app, global_conf):
    """ Functionally equivalent to

    [plugin:form]
    use = repoze.pam.plugins.form.FormPlugin
    rememberer_name = cookie
    login_form_qs=__do_login

    [plugin:cookie]
    use = repoze.pam.plugins.cookie:InsecureCookiePlugin
    cookie_name = oatmeal

    [plugin:basicauth]
    use = repoze.pam.plugins.basicauth.BasicAuthPlugin
    realm = repoze.pam

    [plugin:htpasswd]
    use = repoze.pam.plugins.htpasswd.HTPasswdPlugin
    filename = <...>
    check_fn = repoze.pam.plugins.htpasswd:crypt_check

    [general]
    request_classifier = repoze.pam.classifiers:default_request_classifier
    challenge_decider = repoze.pam.classifiers:default_challenge_decider

    [identifiers]
    plugins = form:browser cookie basicauth

    [authenticators]
    plugins = htpasswd

    [challengers]
    plugins = form:browser basicauth
    """
    # be able to test without a config file
    from repoze.pam.plugins.basicauth import BasicAuthPlugin
    from repoze.pam.plugins.htpasswd import HTPasswdPlugin
    from repoze.pam.plugins.auth_tkt import AuthTktCookiePlugin
    from repoze.pam.plugins.cookie import InsecureCookiePlugin
    from repoze.pam.plugins.form import FormPlugin
    basicauth = BasicAuthPlugin('repoze.pam')
    from StringIO import StringIO
    from repoze.pam.plugins.htpasswd import crypt_check
    io = StringIO()
    salt = 'aa'
    import crypt
    for name, password in [ ('admin', 'admin'), ('chris', 'chris') ]:
        io.write('%s:%s\n' % (name, crypt.crypt(password, salt)))
    io.seek(0)
    htpasswd = HTPasswdPlugin(io, crypt_check)
    auth_tkt = AuthTktCookiePlugin('secret', 'auth_tkt')
    cookie = InsecureCookiePlugin('oatmeal')
    form = FormPlugin('__do_login', rememberer_name='auth_tkt')
    form.classifications = { IIdentifier:['browser'],
                             IChallenger:['browser'] } # only for browser
    identifiers = [('form', form),('auth_tkt',auth_tkt),('basicauth',basicauth)]
    authenticators = [('htpasswd', htpasswd)]
    challengers = [('form',form), ('basicauth',basicauth)]
    from repoze.pam.classifiers import default_request_classifier
    from repoze.pam.classifiers import default_challenge_decider
    log_stream = sys.stdout
    import os
    if os.environ.get('NO_PAM_LOG'):
        log_stream = None
    middleware = PluggableAuthenticationMiddleware(
        app,
        identifiers,
        authenticators,
        challengers,
        default_request_classifier,
        default_challenge_decider,
        log_stream = log_stream,
        log_level = logging.DEBUG
        )
    return middleware

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

class Identity(dict):
    """ dict subclass that prevents its members from being rendered
    during print """
    def __repr__(self):
        return '<repoze.pam identity (hidden, dict-like) at %s>' % id(self)
    __str__ = __repr__
