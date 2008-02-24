from zope.interface import Interface

class IRequestClassifier(Interface):
    """ On ingress: classify a request.

    This interface is responsible for returning a string representing
    a classification name based on introspection of the WSGI
    environment (environ).
    """
    def __call__(environ):
        """ Return a string representing the classification of this
        request. """

class IResponseClassifier(Interface):
    """ On egress: classify a response.

    This interface is responsible for returning a string representing
    a classification name based on introspection of the ingress
    classification, the WSGI environment (environ), the headers
    returned in the response (headers), or the exception raised by a
    downstream application.
    """
    def __call__(environ, request_classification, headers, exception):
        """ Return a string representing the classification of this
        request. """

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

    """ On egress: Initiate a challenge to the user to provide credentials.

        o 'environ' is the WSGI environment.

        o Only challenge plugins which match one of the the current
          request's classifications will be asked to perform a
          challenge.
    """

    def challenge(environ, request_classifier, headers, exception):

        """ Examine the values passed in and perform an arbitrary action
        (usually mutating environ or raising an exception) to cause a
        challenge to be raised to the user.

        The return value of this method is ignored.
        """

