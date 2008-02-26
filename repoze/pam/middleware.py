import logging
from StringIO import StringIO
import sys

from paste.httpheaders import REMOTE_USER

from repoze.pam.interfaces import IIdentifier
from repoze.pam.interfaces import IAuthenticator
from repoze.pam.interfaces import IChallenger

_STARTED = '-- repoze.pam request started --'
_ENDED = '-- repoze.pam request ended --'

class PluggableAuthenticationMiddleware(object):
    def __init__(self, app,
                 identifiers,
                 authenticators,
                 challengers,
                 classifier,
                 challenge_decider,
                 log_stream=None,
                 log_level=logging.INFO
                 ):
        iregistry, nregistry = make_registries(identifiers, authenticators,
                                               challengers)
        self.registry = iregistry
        self.name_registry = nregistry
        self.app = app
        self.classifier = classifier
        self.challenge_decider = challenge_decider
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
        if REMOTE_USER(environ):
            # act as a pass through if REMOTE_USER is already set
            return self.app(environ, start_response)

        environ['repoze.pam.plugins'] = self.name_registry

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
            # auth_ids will be a list of four-tuples; when sorted,
            # its first element will be the "best" identity.  The fourth
            # element in the tuple is the user_id.
            if auth_ids:
                auth_ids.sort()
                best = auth_ids[0]
                identity = best[2]
                userid = best[3]
                identifier = best[1][1]
                environ['REMOTE_USER'] = userid
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
        plugins = self._match_classification(candidates, classification)
        logger and self.logger.info(
            'identifier plugins matched for '
            'classification "%s": %s' % (classification, plugins))

        results = []
        for plugin in plugins:
            identity = plugin.identify(environ)
            if identity:
                logger and logger.debug(
                    'identity returned from %s: %s' % (plugin, identity))
                results.append((plugin, identity))
            else:
                logger and logger.debug(
                    'no identity returned from %s (%s)' % (plugin, identity))

        logger and logger.debug('identities found: %s' % results)
        return results

    def authenticate(self, environ, classification, identities):
        logger = self.logger
        candidates = self.registry.get(IAuthenticator, ())
        logger and self.logger.info('authenticator plugins registered %s' %
                                    candidates)
        plugins = self._match_classification(candidates, classification)
        logger and self.logger.info(
            'authenticator plugins matched for '
            'classification "%s": %s' % (classification, plugins))

        results = []

        auth_rank = 0
        for plugin in plugins:
            identifier_rank = 0
            for identifier, identity in identities:
                userid = plugin.authenticate(environ, identity)
                if userid:
                    logger and logger.debug(
                        'userid returned from %s: %s' % (plugin, userid))
                    tup = ( (auth_rank, plugin),
                            (identifier_rank, identifier),
                            identity,
                            userid
                            )
                    results.append(tup)
                else:
                    logger and logger.debug(
                        'no userid returned from %s: (%s)' % (plugin, userid))
                identifier_rank += 1
            auth_rank += 1

        logger and logger.debug('identities authenticated: %s' % results)
        return results

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
        plugins = self._match_classification(candidates, classification)
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

    def _match_classification(self, plugins, classification):
        result = []
        for plugin in plugins:
            plugin_classifications = getattr(plugin, 'classifications', None)
            if not plugin_classifications: # good for any
                result.append(plugin)
                continue
            if classification in plugin_classifications:
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
    from repoze.pam.plugins.cookie import InsecureCookiePlugin
    from repoze.pam.plugins.form import FormPlugin
    basicauth = BasicAuthPlugin('repoze.pam')
    any = None # means good for any classification
    basicauth.classifications = any
    from StringIO import StringIO
    from repoze.pam.plugins.htpasswd import crypt_check
    io = StringIO()
    salt = 'aa'
    import crypt
    for name, password in [ ('admin', 'admin'), ('chris', 'chris') ]:
        io.write('%s:%s\n' % (name, crypt.crypt(password, salt)))
    io.seek(0)
    htpasswd = HTPasswdPlugin(io, crypt_check)
    htpasswd.classifications = any
    cookie = InsecureCookiePlugin('oatmeal')
    cookie.classifications = any
    form = FormPlugin('__do_login', rememberer_name='cookie')
    form.classifications = set(('browser',)) # only for for browser requests
    identifiers = [('form', form),('cookie',cookie),('basicauth',basicauth) ]
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
        log_stream= log_stream,
        log_level = logging.DEBUG
        )
    return middleware

def verify(plugin, iface):
    from zope.interface.verify import verifyObject
    verifyObject(iface, plugin, tentative=True)
    
def make_registries(identifiers, authenticators, challengers):
    from zope.interface.verify import BrokenImplementation
    interface_registry = {}
    name_registry = {}

    for supplied, iface in [ (identifiers, IIdentifier),
                             (authenticators, IAuthenticator),
                             (challengers, IChallenger) ]:
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


