from zope.interface import Interface

class IRequestClassifier(Interface):
    """ On ingress: classify a request.
    """
    def __call__(environ):
        """ environ -> request classifier string

        This interface is responsible for returning a string
        value representing a request classification.

        o 'environ' is the WSGI environment.
        """

class IResponseClassifier(Interface):
    """ On egress: classify a response.
    """
    def __call__(environ, request_classification, status, headers):
        """ args -> response classifier string

        This interface is responsible for returning a string representing
        a response classification.

        o 'environ' is the WSGI environment.

        o 'request_classification' is the classification returned during
          ingress by the request classifier.

        o 'status' is the status written into start_response by
          the downstream application.

        o 'headers' is the headers tuple written into start_response
          by the downstream application.
          """

class IExtractorPlugin(Interface):

    """ On ingress: Extract credentials from the WSGI environment.
    """

    def extract(environ):
        """ environ -> { 'login' : login 
                       , 'password' : password 
                       , k1 : v1
                       ,   ...
                       , kN : vN
                       } | {}

        o 'environ' is the WSGI environment.

        o If credentials are found, the returned mapping will contain at
          least 'login', 'password', 'remote_host' and 'remote_addr' keys.

        o Return an empty mapping to indicate that the plugin found no
          appropriate credentials.

        o Only extraction plugins which match one of the the current
          request's classifications will be asked to perform extraction.
        """

class IPostExtractorPlugin(Interface):
    """ On ingress: allow the plugin to have a chance to influence the
    environment once credentials are established and return extra
    headers that will be set in the eventual response.

    Each post-extractor matching the request classification is called
    unconditionally after extraction.
    """

    def post_extract(environ, credentials, extractor):
        """ args -> [ (header-name, header-value), ..] | None

        o 'environ' is the WSGI environment.

        o credentials are the credentials that were extracted by
          repoze.pam during the extraction step.

        o 'extractor' is the plugin instance that provided the
          credentials.  If no plugin instance provided credentials to
          repoze.pam, this will be None.

        The return value should be a list of tuples, where each tuple is
        in the form (header-name, header-value), e.g.
        [ ('Set-Cookie', 'cookie_name=foo; Path=/') ] or None if
        no headers should be set.
        """

class IAuthenticatorPlugin(Interface):

    """ On ingress: Map credentials to a user ID.
    """

    def authenticate(environ, credentials):
        """ credentials -> userid

        o 'environ' is the WSGI environment.

        o 'credentials' will be a mapping, as returned by IExtractionPlugin.

        o If credentials are found, the userid will be returned; this will
          be the value placed into the REMOTE_USER key in the environ
          to be used by downstream applications.

        o If the credentials cannot be authenticated, None will be returned.
        """

class IChallengerPlugin(Interface):

    """ On egress: Conditionally initiate a challenge to the user to
        provide credentials.

        Only challenge plugins which match one of the the current
        response's classifications will be asked to perform a
        challenge.
    """

    def challenge(environ, status, headers):
        """ args -> WSGI application or None

        o 'environ' is the WSGI environment.

        o 'status' is the status written into start_response by the
          downstream application.

        o 'headers' is the headers tuple written into start_response by the
          downstream application.

        Examine the values passed in and return a WSGI application
        (a callable which accepts environ and start_response as its
        two positional arguments, ala PEP 333) which causes a
        challenge to be performed.  Return None to forego performing a
        challenge.
        """

