from repoze.pam.interfaces import IAuthenticatorPlugin
from repoze.pam.interfaces import IExtractorPlugin
from repoze.pam.interfaces import IChallengerPlugin

class PluggableAuthenticationMiddleware(object):
    def __init__(self, app, registry, request_classifier, response_classifier,
                 add_credentials=True):
        self.registry = registry
        self.app = app
        self.request_classifier = request_classifier
        self.response_classififer = response_classifier
        self.add_credentials = add_credentials

    def __call__(self, environ, start_response):
        request_classification = self.on_ingress(environ)
        return self.app(environ, start_response)
        # XXX on_egress

    def on_ingress(self, environ):
        classification = self.request_classifier(environ)
        credentials = self.extract(environ, classification)

        if credentials:
            userid = self.authenticate(environ, credentials, classification)

        if self.add_credentials:
            credentials['userid'] = userid
            environ['repoze.pam.credentials'] = credentials

        if userid:
            environ['REMOTE_USER'] = userid

        return classification

    def on_egress(self, environ, request_classifier, headers, exception):
        self.challenge(environ, request_classifier, headers, exception)

    def extract(self, environ, classifier):
        extractor_candidates = self.registry.get(IExtractorPlugin)
        extractors = self._match_classifier(extractor_candidates, classifier)

        for extractor in extractors:
            creds = extractor.extract(environ)
            if creds:
                # XXX PAS returns all credentials (it fully iterates over all
                # extraction plugins)
                return creds
        return {}

    def authenticate(self, environ, credentials, classification):
        # on ingress
        userid = None
        auth_candidates = self.registry.get(IAuthenticatorPlugin)
        authenticators = self._match_classifier(auth_candidates, classification)
        for authenticator in authenticators:
            userid = authenticator.authenticate(environ, credentials)
            if userid:
                # XXX PAS calls all authenticators (it fully iterates over all
                # authenticator plugins)
                break
        return userid

    def challenge(self, environ, request_classification, headers, exception):
        # on egress
        classification = self.response_classifier(environ,
                                                  request_classification,
                                                  headers,
                                                  exception)
        challenger_candidates = self.registry.get(IChallengerPlugin)
        challengers = self._match_classifier(challenger_candidates,
                                              classification)
        for challenger in challengers:
            new_headers, new_status = challengers.challenge(environ)

    def _match_classifier(self, plugins, classifier):
        result = []
        for plugin in plugins:
            plugin_classifiers = getattr(plugin, 'classifiers', set())
            if not plugin_classifiers: # good for any
                result.append(plugin)
                continue
            if classifier in plugin_classifiers:
                result.append(plugin)
                    
        return result

def make_middleware(app, global_conf, config_file=None):
    if config_file is None:
        raise ValueError('config_file must be specified')
    return PluggableAuthenticationMiddleware(app)

def make_test_middleware(app, global_conf):
    # no config file required
    from repoze.pam.plugins.basicauth import BasicAuthPlugin
    from repoze.pam.plugins.htpasswd import HTPasswdPlugin
    basicauth = BasicAuthPlugin('repoze.pam')
    basicauth.classifiers = set() # good for any
    from StringIO import StringIO
    io = StringIO('chrism:aajfMKNH1hTm2\n')
    htpasswd = HTPasswdPlugin(io)
    htpasswd.classifiers = set() # good for any
    registry = make_registry((htpasswd,), (basicauth,), (basicauth,))
    class DummyClassifier:
        def classify(self, *arg, **kw):
            return None
    classifier = DummyClassifier()
    middleware = PluggableAuthenticationMiddleware(app, registry,
                                                   classifier, classifier)
    return middleware

def verify(plugins, iface):
    from zope.interface.verify import verifyObject
    for plugin in plugins:
        verifyObject(iface, plugin, tentative=True)
    
def make_registry(extractors, authenticators, challengers):
    registry = {}
    verify(extractors, IExtractorPlugin)
    registry[IExtractorPlugin] = extractors
    verify(authenticators, IAuthenticatorPlugin)
    registry[IAuthenticatorPlugin] = authenticators
    verify(challengers, IChallengerPlugin)
    registry[IChallengerPlugin] = challengers
    return registry

