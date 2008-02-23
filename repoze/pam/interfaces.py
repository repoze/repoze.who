from zope.interface import Interface

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

        o If the credentials cannot be authenticated, return None.
        """

class IChallengerPlugin(Interface):

    """ On ingress: Initiate a challenge to the user to provide credentials.

        o 'environ' is the WSGI environment.

        o Challenge plugins have an attribute 'protocols' representing
          the protocols the plugin operates under, defaulting to None.

        o Only challenge plugins which match the current request's
          protocol will be asked to perform a challenge.

        o If no challenge plugins satisfy the current request's
          protocol, a default exception will be raised.

        o If no challenge plugins themselves raise an exception, a
          default exception will be raised.
    """

    def challenge(environ):

        """ Examine the environ and perform one of the following two
        actions:

        - Raise an exception which can be interpreted by
          left-hand-side middleware should gather credentials
          (present a form, show a basic auth dialog).

        - Do nothing.

        The return value of this method is ignored.
        """

class ICredentialsUpdaterPlugin(Interface):

    """ On egress:  user has changed her password.

    This interface is not responsible for the actual password change,
    it is used after a successful password change event in a
    downstream application.

    It is called when the repoze.pam middleware intercepts a
    'repoze.pam.update' key in the WSGI environ during egress.
    """

    def update(environ, login, new_password):

        """ Scribble as appropriate.
        """

class ILogoutPlugin(Interface):

    """ On egress:  user has logged out.

    It is called when the repoze.pam middleware intercepts an
    ResetCredentialsException from downstream middleware.

    It is called when the repoze.pam middleware intercepts a
    'repoze.pam.reset' key in the WSGI environ during egress.
    """

    def logout(environ):

        """ Scribble as appropriate.
        """

