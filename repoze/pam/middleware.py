import logging
from StringIO import StringIO
import sys

from paste.httpheaders import REMOTE_USER

from repoze.pam.interfaces import IAuthenticatorPlugin
from repoze.pam.interfaces import IExtractorPlugin
from repoze.pam.interfaces import IPostExtractorPlugin
from repoze.pam.interfaces import IChallengerPlugin

class StartResponseWrapper(object):
    def __init__(self, start_response, extra_headers):
        self.start_response = start_response
        self.extra_headers = extra_headers
        self.headers = []
        self.buffer = StringIO()

    def wrap_start_response(self, status, headers, exc_info=None):
        self.headers = headers
        self.status = status
        return self.buffer.write

    def finish_response(self):
        headers = self.headers + self.extra_headers
        write = self.start_response(self.status, headers)
        if write:
            self.buffer.seek(0)
            write(self.buffer.getvalue())
            if hasattr(write, 'close'):
                write.close()

_STARTED = '-- repoze.pam request started --'
_ENDED = '-- repoze.pam request ended --'

class PluggableAuthenticationMiddleware(object):
    def __init__(self, app,
                 registry,
                 request_classifier,
                 response_classifier,
                 add_credentials=False,
                 log_stream=None,
                 log_level=logging.INFO):
        self.registry = registry
        self.app = app
        self.request_classifier = request_classifier
        self.response_classifier = response_classifier
        self.add_credentials = add_credentials
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
        logger = self.logger
        logger and logger.info(_STARTED)
        classification, extra_headers = self.modify_environment(environ)

        wrapper = StartResponseWrapper(start_response, extra_headers)
        app_iter = self.app(environ, wrapper.wrap_start_response)

        challenge_app = self.challenge(
            environ,
            classification,
            wrapper.status,
            wrapper.headers
            )
        logger and logger.info('challenge app used: %s' % challenge_app)

        if challenge_app is not None:
            if hasattr(app_iter, 'close'):
                app_iter.close()
            logger and logger.info(_ENDED)
            return challenge_app(environ, start_response)
        else:
            wrapper.finish_response()
            logger and logger.info(_ENDED)
            return app_iter

    def modify_environment(self, environ):
        # happens on ingress
        classification = self.request_classifier(environ)
        logger = self.logger
        logger and logger.info('request classification: %s' % classification)
        credentials, extractor = self.extract(environ, classification)
        headers = self.after_extract(environ, credentials, extractor,
                                     classification)
        userid = None

        if credentials:
            userid, authenticator = self.authenticate(environ,
                                                      credentials,
                                                      classification)
        else:
            logger and logger.info(
                'no authenticator plugin used (no credentials)')

        if self.add_credentials:
            environ['repoze.pam.credentials'] = credentials

        remote_user_not_set = not REMOTE_USER(environ)

        if remote_user_not_set and userid:
            # only set REMOTE_USER if it's not yet set
            logger and logger.info('REMOTE_USER set to %s' % userid)
            environ['REMOTE_USER'] = userid
        else:
            logger and logger.info('REMOTE_USER not set')

        return classification, headers
        
    def extract(self, environ, classification):
        # happens on ingress
        candidates = self.registry.get(IExtractorPlugin, ())
        plugins = self._match_classification(candidates, classification,
                                             'request_classifications')
        logger = self.logger
        logger and self.logger.info(
            'extractor plugins consulted %s' % plugins)

        for plugin in plugins:
            creds = plugin.extract(environ)
            logger and logger.debug(
                'credentials returned from extractor %s: %s' %
                (plugin, creds)
                )
            if creds:
                # XXX PAS returns all credentials (it fully iterates over all
                # extraction plugins)
                logger and logger.info(
                    'using credentials returned from extractor %s' % plugin)
                return creds, plugin
        logger and logger.info('no extractor plugins found credentials')
        return {}, None

    def after_extract(self, environ, credentials, extractor, classification):
        candidates = self.registry.get(IPostExtractorPlugin, ())
        plugins = self._match_classification(candidates,
                                             classification,
                                             'request_classifications')
        logger = self.logger
        logger and logger.info(
            'post-extractor plugins consulted %s' % plugins)

        extra_headers = {}
        for plugin in plugins:
            headers = plugin.post_extract(environ, credentials, extractor)
            logger and logger.debug(
                'headers returned from post-extractor %s: %s' %
                (plugin, headers)
                )
            if headers:
                extra_headers[plugin] = headers

        logger and logger.info('extra headers gathered: %s' % extra_headers)

        return flatten(extra_headers.values())

    def authenticate(self, environ, credentials, classification):
        # happens on ingress
        candidates = self.registry.get(IAuthenticatorPlugin, ())
        plugins = self._match_classification(candidates,
                                             classification,
                                             'request_classifications')
        logger = self.logger

        logger and logger.info(
            'authenticator plugins consulted %s' % plugins)

        for plugin in plugins:
            userid = plugin.authenticate(environ, credentials)
            logger and logger.info(
                'userid returned from authenticator %s: %s' %
                (plugin, userid)
                )
            if userid:
                logger and logger.info(
                    'using userid returned from authenticator %s' % plugin)
                return userid, plugin

        logger and logger.info('no authenticator plugin authenticated a userid')
        return None, None

    def challenge(self, environ, request_classification, status, headers):
        # happens on egress
        classification = self.response_classifier(
            environ,
            request_classification,
            status,
            headers
            )

        logger = self.logger
        logger and logger.info('response classification: %s' % classification)

        candidates = self.registry.get(IChallengerPlugin, ())
        plugins = self._match_classification(candidates,
                                             classification,
                                             'response_classifications')
        logger and logger.info('challenger plugins consulted: %s' % plugins)
        for plugin in plugins:
            app = plugin.challenge(environ, status, headers)
            logger and logger.debug('app returned from challenger %s: %s' %
                                    (plugin, app)
                                    )
            if app is not None:
                # new WSGI application
                logger and logger.info(
                    'challenger plugin %s returned an app: %s' % (plugin, app))
                return app
        logger and logger.info('no challenge app returned')
        # signifies no challenge
        return None

    def _match_classification(self, plugins, classification, attr):
        result = []
        for plugin in plugins:
            plugin_classifications = getattr(plugin, attr, None)
            if not plugin_classifications: # good for any
                result.append(plugin)
                continue
            if classification in plugin_classifications:
                result.append(plugin)
                    
        return result

def flatten(L):
    result = []
    for seq in L:
        for item in seq:
            result.append(item)
    return result

def make_middleware(app, global_conf, config_file=None):
    if config_file is None:
        raise ValueError('config_file must be specified')
    return PluggableAuthenticationMiddleware(app)

def make_test_middleware(app, global_conf):
    # be able to test without a config file
    from repoze.pam.plugins.basicauth import BasicAuthPlugin
    from repoze.pam.plugins.htpasswd import HTPasswdPlugin
    from repoze.pam.plugins.cookie import InsecureCookiePlugin
    from repoze.pam.plugins.form import FormPlugin
    basicauth = BasicAuthPlugin('repoze.pam')
    any = set() # means good for any classification
    basicauth.request_classifications = any
    basicauth.response_classifications = any
    from StringIO import StringIO
    from repoze.pam.plugins.htpasswd import crypt_check
    io = StringIO()
    salt = 'aa'
    import crypt
    for name, password in [ ('admin', 'admin') ]:
        io.write('name:%s\n' % crypt.crypt(password, salt))
    htpasswd = HTPasswdPlugin(io, crypt_check)
    htpasswd.request_classifications = any
    htpasswd.response_classifications = any
    cookie = InsecureCookiePlugin('oatmeal')
    cookie.request_classifications = any
    cookie.response_classifications = any
    form = FormPlugin('__do_login')
    # only do form extract/challenge for browser requests
    form.request_classifications = set(('browser',)) 
    form.response_classifications = set(('browser',)) 
    registry = make_registry(
        extractors = (cookie, basicauth, form),
        post_extractors = (cookie, basicauth),
        authenticators = (htpasswd,),
        challengers = (form, basicauth),
        )
    from repoze.pam.classifiers import DefaultRequestClassifier
    from repoze.pam.classifiers import DefaultResponseClassifier
    request_classifier = DefaultRequestClassifier()
    response_classifier = DefaultResponseClassifier()
    middleware = PluggableAuthenticationMiddleware(app,
                                                   registry,
                                                   request_classifier,
                                                   response_classifier,
                                                   log_stream=sys.stdout,
                                                   log_level = logging.DEBUG
                                                   )
    return middleware

def verify(plugins, iface):
    from zope.interface.verify import verifyObject
    for plugin in plugins:
        verifyObject(iface, plugin, tentative=True)
    
def make_registry(extractors, post_extractors, authenticators, challengers):
    registry = {}
    verify(extractors, IExtractorPlugin)
    registry[IExtractorPlugin] = extractors
    verify(post_extractors, IExtractorPlugin)
    registry[IPostExtractorPlugin] = post_extractors
    verify(authenticators, IAuthenticatorPlugin)
    registry[IAuthenticatorPlugin] = authenticators
    verify(challengers, IChallengerPlugin)
    registry[IChallengerPlugin] = challengers
    return registry

