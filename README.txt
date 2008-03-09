repoze.pam

Overview

  repoze.pam (Pluggable Authentication Middleware) is an
  identification and authentication framework for WSGI. 

Description

  repoze.pam's ideas are largely culled from Zope 2's Pluggable
  Authentication Service (PAS) (but repoze.pam is not dependent on
  Zope 2 in any way).  Unlike PAS, it provides no facilities for
  creating user objects, assigning roles or groups to users,
  retrieving or changing user properties, or enumerating users,
  groups, or roles.  These responsibilities are assumed to be the
  domain of the WSGI application you're serving.  It also provides no
  facility for authorization (ensuring whether a user can or cannot
  perform the operation implied by the request).  This is also the
  domain of the WSGI application.
 
  It attemtps to reuse implementations from paste.auth for some of its
  functionality.

Middleware Responsibilities

  repoze.pam's middleware has one major function on ingress: it
  conditionally places identification and authentication information
  (including a REMOTE_USER value) into the WSGI environment and allows
  the request to continue to a downstream WSGI application.

  repoze.pam's middleware has one major function on egress: it
  examines the headers set by the downstream application, the WSGI
  environment, or headers supplied by other plugins and conditionally
  challenges for credentials.

PasteDeploy Configuration

Classifiers

  repoze.pam "classifies" the request on middleware ingress.  Request
  classification happens before identification and authentication.  A
  request from a browser might be classified a different way that a
  request from an XML-RPC client.  repoze.pam uses request classifiers
  to decide which other components to consult during subsequent
  identification, authentication, and challenge steps.  Plugins are
  free to advertise themselves as willing to participate in
  identification and authorization for a request based on this
  classification.

  The classification system is pluggable.  repoze.pam provides a
  default classifier that you may use.  You may extend the
  classification system by making repoze.pam aware of a different
  classifier implementation.

Plugins

  repoze.pam is designed around the concept of plugins.  Plugins are
  instances that are willing to perform one or more identification-
  and/or authentication-related duties.  When you register a plugin,
  you register a plugin factory, which is a callable that accepts
  configuration parameters.  The callable must return an instance of a
  plugin when called.  Each plugin can be configured arbitrarily using
  values in a repoze.pam-specific configuration file.

  repoze.pam consults the set of configured plugins when it intercepts
  a WSGI request, and gives some subset of them a chance to influence
  what is added to the WSGI environment.

Request (Ingress) Stages

  repoze.pam performs the following operations in the following order
  during middleware ingress:

  1.  Request Classification

      The WSGI environment is examined and the request is classified
      into one "type" of request.  The callable named as
      'request_classifer=' within the '[general]' section is used to
      perform the classification.  It returns a value that is
      considered to be the request classification.

  2.  Identification

      Identifiers which nominate themselves as willing to extract data
      for a particular class of request (as provided by the request
      classifier) will be consulted to retrieve credentials data from
      the environment.  For example, a basic auth identifier might use
      the HTTP_AUTHORIZATION header to find login and password
      information.  Identifiers are also responsible for providing
      header information to set and remove authentication information
      in the response.

  3.  Authentication

      Authenticators which nominate themselves as willing to
      authenticate for a particular class of request will be consulted
      to compare information provided by the identification plugins
      that returned credentials.  For example, an htpasswd
      authenticator might look in a file for a user record matching
      any of the identities.  If it finds one, and if the password
      listed in the record matches the password provided by an
      identity, the userid of the user would be returned (which would
      be the same as the login name).

Response (Egress) Stages

  repoze.pam performs the following operations in the following order
  during middleware egress:

  1.  Challenge Decision

      The WSGI environment and the status and headers returned by the
      downstream application may be examined to determine whether a
      challenge is required.  Typically, only the status is used (if
      it starts with "401 ", a challenge is required).  This behavior
      is pluggable.

  2.  Challenge

      Challengers which nominate themselves as willing to execute a
      challenge for a particular class of request (as provided by the
      classifier) will be consulted, and one will be chosen to perform
      a challenge.  A challenger plugin can use application-returned
      headers, the WSGI environment, and other items to determine what
      sort of operation should be performed to actuate the challenge.
      Note that repoze.pam defers to the identifier plugin which
      provided the identity (if any) to reset credentials at challenge
      time; this is not the responsibility of the challenger.

Plugin Types

  Identifier Plugins

    You can register a plugin as willing to act as an "identifier".
    An identifier examines the WSGI environment and attempts to
    extract credentials from the environment.  These credentials are
    used by authenticator plugins to perform authentication.  In some
    cases, an identification plugin can "preauthenticate" an identity
    (and can thus act as an authenticator plugin).

  Authenticator Plugins

    You may register a plugin as willing to act as an "authenticator".
    Authenticator plugins are responsible for resolving a set of
    credentials provided by an identifier plugin into a user id.
    Typically, authenticator plugins will perform a lookup into a
    database or some other persistent store, check the provided
    credentials against the stored data, and return a user id if the
    credentials can be validated.

    The user id provided by an authenticator is eventually passed to
    downstream WSGI applications in the "REMOTE_USER' environment
    variable.

  Challenger Plugins

    You may register a plugin as willing to act as a "challenger".
    Challenger plugins are responsible for initiating a challenge to
    the requesting user.  Challenger plugins are invoked by repoze.pam
    when it decides a challenge is necessary. A challenge might
    consist of displaying a form or presenting the user with a basic
    or digest authentication dialog.

Configuration File Example

  repoze.pam is configured using a ConfigParser-style .INI file.  The
  configuration file has five main types of sections: plugin sections,
  a general section, an identifiers section, an authenticators section,
  and a challengers section.  Each "plugin" section defines a
  configuration for a particular plugin.  The identifiers,
  authenticators, and challengers sections refer to these plugins to
  form a site configuration.  The general section is general middleware
  configuration.

Example repoze.pam Configuration File (*NOTE: SCIENCE FICTION, not yet
implemented!*)

  repoze.pam is designed to be used within a PasteDeploy configuration
  file:

    [filter:pam]
    use = egg:repoze.pam#pam
    config_file = %(here)s/pam.ini

  Below is an example of a configuration file that might be used to
  configure the repoze.pam middleware.  A set of plugins are defined,
  and they are referred to by following non-plugin sections.

  In the below configuration, five plugins are defined.  The form, and
  basicauth plugins are nominated to act as challenger plugins.  The
  form, cookie, and basicauth plugins are nominated to act as
  identification plugins.  The htpasswd and sqlusers plugins are
  nominated to act as authenticator plugins.

    [plugin:form]
    # identificaion and challenge
    login_form_qs = __do_login
    identifier_impl_name = cookie

    [plugin:cookie]
    # identification
    use = egg:repoze.pam#cookie
    cookie_name = repoze.pam.auth

    [plugin:basicauth]
    # identification and challenge
    use = egg:repoze.pam#basicauth
    realm = repoze

    [plugin:htpasswd]
    # authentication
    use = egg:repoze.pam#htpasswd
    filename = %(here)s/users.htpasswd
    check_fn = egg:repoze.pam#crypt_check

    [plugin:sqlusers]
    # authentication
    use = egg:repoze.pam#squsersource
    db = sqlite://database?user=foo&pass=bar
    get_userinfo = select id, password from users
    check_fn = egg:repoze.pam#crypt_check

    [general]
    request_classifier = egg:repoze.pam#defaultrequestclassifier
    challenge_decider = egg:repoze.pam#defaultchallengedecider

    [identifiers]
    # plugin_name:classifier_name:.. or just plugin_name (good for any)
    plugins =
          form:browser
          cookie
          basicauth

    [authenticators]
    # plugin_name:classifier_name.. or just plugin_name (good for any)
    plugins =
          htpasswd
          sqlusers

    [challengers]
    # plugin_name:classifier_name:.. or just plugin_name (good for any)
    plugins =
          form:browser
          basicauth

Further Description of Example Config

  The basicauth section configures a plugin that does identification
  and challenge for basic auth credentials.  The form section
  configures a plugin that does identification and challenge (its
  implementation defers to the cookie plugin for identification
  "forget" and "remember" duties, thus the "identifier_impl_name" key;
  this is looked up at runtime).  The cookie section configures a
  plugin that does identification for cookie auth credentials.  The
  htpasswd plugin obtains its user info from a file.  The sqlusers
  plugin obtains its user info from a sqlite database.

  The identifiers section provides an ordered list of plugins that are
  willing to provide identification capability.  These will be
  consulted in the defined order.  The tokens on each line of the
  'plugins=' key are in the form
  "plugin_name:requestclassifier_name:..."  (or just "plugin_name" if
  the plugin can be consulted regardless of the classification of the
  request).  The configuration above indicates that the system will
  look for credentials using the form plugin (if the request is
  classified as a browser request), then the cookie identifier
  (unconditionally), then the basic auth plugin (unconditionally).

  The authenticators section provides an ordered list of plugins that
  provide authenticator capability.  These will be consulted in the
  defined order, so the system will look for users in the file, then
  in the sql database when attempting to validate credentials.  No
  classification prefixes are given to restrict which of the two
  plugins are used, so both plugins are consulted regardless of the
  classification of the request.  Each authenticator is called with
  each set of identities found by the identifier plugins.  The first
  identity that can be authenticated is used to set "REMOTE_USER".

  The challengers section provides an ordered list of plugins that
  provide challenger capability.  These will be consulted in the
  defined order, so the system will consult the cookie auth plugin
  first, then the basic auth plugin.  Each will have a chance, based
  on the response classification, to initiate a challenge.  The above
  configuration indicates that the form challenger will fire if it's a
  browser request, and the basic auth challenger will fire if it's not
  (fallback).

Writing An Identifier Plugin

  An identifier plugin (aka an IIdentifier plugin) must do three
  things: extract credentials from the request and turn them into an
  "identity", "remember" credentials, and "forget" credentials.

  Here's a simple cookie identification plugin that does these three
  things::

    class InsecureCookiePlugin(object):

        def __init__(self, cookie_name):
            self.cookie_name = cookie_name

        def identify(self, environ):
            cookies = get_cookies(environ)
            cookie = cookies.get(self.cookie_name)

            if cookie is None:
                return None

            import binascii
            try:
                auth = cookie.value.decode('base64')
            except binascii.Error: # can't decode
                return None

            try:
                login, password = auth.split(':', 1)
                return {'login':login, 'password':password}
            except ValueError: # not enough values to unpack
                return None

        def remember(self, environ, identity):
            cookie_value = '%(login)s:%(password)s' % identity
            cookie_value = cookie_value.encode('base64').rstrip()
            from paste.request import get_cookies
            cookies = get_cookies(environ)
            existing = cookies.get(self.cookie_name)
            value = getattr(existing, 'value', None)
            if value != cookie_value:
                # return a Set-Cookie header
                set_cookie = '%s=%s; Path=/;' % (self.cookie_name, cookie_value)
                return [('Set-Cookie', set_cookie)]

        def forget(self, environ, identity):
            # return a expires Set-Cookie header
            expired = ('%s=""; Path=/; Expires=Sun, 10-May-1971 11:59:00 GMT' %
                       self.cookie_name)
            return [('Set-Cookie', expired)]
        
        def __repr__(self):
            return '<%s %s>' % (self.__class__.__name__, id(self))

  Note that the plugin implements three "interface" methods:
  "identify", "forget" and "remember".  The formal specification for
  the arguments and return values expected from these methods are
  available in the "interfaces.py" file in repoze.pam as the
  'IIdentifier' interface, but let's examine them less formally one at
  a time.

  identify(environ) --

    The 'identify' method of our InsecureCookiePlugin accepts a single
    argument "environ".  This will be the WSGI environment dictionary.
    Our plugin attempts to grub through the cookies sent by the
    client, trying to find one that matches our cookie name.  If it
    finds one that matches, it attempts to decode it and turn it into
    a login and a password, which it returns as values in a
    dictionary.  This dictionary is thereafter known as an "identity".
    If it finds no credentials in cookies, it returns None (which is
    not considered an identity).

    More generally, the 'identify' method of an IIdentifier plugin is
    called once on WSGI request "ingress", and it is expected to grub
    arbitrarily through the WSGI environment looking for credential
    information.  In our above plugin, the credential information is
    expected to be in a cookie but credential information could be in
    a cookie, a form field, basic/digest auth information, a header, a
    WSGI environment variable set by some upstream middleware or
    whatever else someone might use to stash authentication
    information.  If the plugin finds credentials in the request, it's
    expected to return an "identity": this must be a dictionary.  The
    dictionary is not required to have any particular keys or value
    composition, although it's wise if the identification plugin looks
    for both a login name and a password information to return at
    least {'login':login_name, 'password':password}, as some
    authenticator plugins may depend on presence of the names "login"
    and "password" (e.g. the htpasswd and sql IAuthenticator plugins).
    If an IIdentifier plugin finds no credentials, it is expected to
    return None.

    An IIdentifier plugin is also permitted to "preauthenticate" an
    identity.  If the identifier plugin knows that the identity is
    "good" (e.g. in the case of ticket-based authentication where the
    userid is embedded into the ticket), it can insert a special key
    into the identity dictionary: 'repoze.pam.userid'.  If this key is
    present in the identity dictionary, no authenticators will be
    asked to authenticate the identity.  This effectively alllows an
    IIdentifier plugin to become an IAuthenticator plugin when
    breaking apart the responsibility into two separate plugins is
    "make-work".  Preauthenticated identities will be selected first
    when deciding which identity to use for any given request.  Our
    cookie plugin doesn't use this feature.

  remember(environ, identity) --

    If we've passed a REMOTE_USER to the WSGI application during
    ingress (as a result of providing an identity that could be
    authenticated), and the downstream application doesn't kick back
    with an unauthorized response, on egress we want the requesting
    client to "remember" the identity we provided if there's some way
    to do that and if he hasn't already, in order to ensure he will
    pass it back to us on subsequent requests without requiring
    another login.  The remember method of an IIdentifier plugin is
    called for each non-unauthenticated response.  It is the
    responsibility of the IIdentifier plugin to conditionally return
    HTTP headers that will cause the client to remember the
    credentials implied by "identity".
    
    Our InsecureCookiePlugin implements the "remember" method by
    returning headers which set a cookie if and only if one is not
    already set with the same name and value in the WSGI environment.
    These headers will be tacked on to the response headers provided
    by the downstream application during the response.

    When you write a remember method, most of the work involved is
    determining *whether or not* you need to return headers.  It's
    typical to see remember methods that compute an "old state" and a
    "new state" and compare the two against each other in order to
    determine if headers need to be returned.  In our example
    InsecureCookiePlugin, the "old state" is "cookie_value" and the
    "new state" is "value".

  forget(environ, identity) --

    Eventually the WSGI application we're serving will issue a "401
    Unauthorized" or another status signifying that the request could
    not be authorized.  repoze.pam intercepts this status and calls
    IIdentifier plugins asking them to "forget" the credentials
    implied by the identity.  It is the "forget" method's job at this
    point to return HTTP headers that will effectively clear any
    credentials on the requesting client implied by the "identity"
    argument.

    Our InsecureCookiePlugin implements the "forget" method by
    returning a header which resets the cookie that was set earlier by
    the remember method to one that expires in the past (on my
    birthday, in fact).  This header will be tacked onto the response
    headers provided by the downstream application.

Writing an Authenticator Plugin

  An authenticator plugin (aka an IAuthenticator plugin) must do only
  one thing (on "ingress"): accept an identity and check if the
  identity is "good".  If the identity is good, it should return a
  "user id".  This user id may or may not be the same as the "login"
  provided by the user.  An IAuthenticator plugin will be called for
  each identity found during the identification phase (there may be
  multiple identities for a single request, as there may be multiple
  IIdentifier plugins active at any given time), so it may be called
  multiple times in the same request.

  Here's a simple authenticator plugin that attempts to match an
  identity against ones defined in an "htpasswd" file that does just
  that::

    class SimpleHTPasswdPlugin(object):

        def __init__(self, filename):
            self.filename = filename

        # IAuthenticatorPlugin
        def authenticate(self, environ, identity):
            try:
                login = identity['login']
                password = identity['password']
            except KeyError:
                return None

            f = open(self.filename, 'r')

            for line in f:
                try:
                    username, hashed = line.rstrip().split(':', 1)
                except ValueError:
                    continue
                if username == login:
                    if crypt_check(password, hashed):
                        return username
            return None

    def crypt_check(password, hashed):
        from crypt import crypt
        salt = hashed[:2]
        return hashed == crypt(password, salt)

  Note that the plugin implements a single "interface" method:
  "authenticate".  The formal specification for the arguments and
  return values expected from this method is available in the
  "interfaces.py" file in repoze.pam as the 'IAuthenticator'
  interface, but we can explore this a little further here.

  The 'authenticate' method accepts two arguments: the WSGI
  environment and an identity.  Our SimpleHTPasswdPlugin
  'authenticate' implementation grabs the login and password out of
  the identity and attempts to find the login in the htpasswd file.
  If it finds it, it compares the crypted version of the password
  provided by the user to the crypted version stored in the htpasswd
  file, and finally, if they match, it returns the login.  If they do
  not match, it returns None.

  Note that our plugin does not assume that the keys 'login' or
  'password' exist in the identity; although it requires them to do
  "real work" it returns None if they are not present instead of
  raising an exception.  This is required by the IAuthenticator
  interface specification.

Writing a Challenger Plugin

  A challenger plugin (aka an IChallenger plugin) must do only one
  thing on "egress": return a WSGI application which performs a
  "challenge".  A WSGI application is a callable that accepts an
  "environ" and a "start_response" as its parameters; see "PEP 333"
  for further definition of what a WSGI application.  A challenge asks
  the user for credentials.

  Here's an example of a simple challenger plugin::

    from paste.httpheaders import WWW_AUTHENTICATE
    from paste.httpexceptions import HTTPUnauthorized

    class BasicAuthChallengerPlugin(object):

        def __init__(self, realm):
            self.realm = realm

        # IChallenger
        def challenge(self, environ, status, app_headers, forget_headers):
            head = WWW_AUTHENTICATE.tuples('Basic realm="%s"' % self.realm)
            if head[0] not in forget_headers:
                head = head + forget_headers
            return HTTPUnauthorized(headers=head)

  Note that the plugin implements a single "interface" method:
  "challenge".  The formal specification for the arguments and return
  values expected from this method is available in the "interfaces.py"
  file in repoze.pam as the 'IChallenger' interface.  This method is
  called when repoze.pam determines that the application has returned
  an "unauthorized" response (e.g. a 401).  Only one challenger will
  be consulted during "egress" as necessary (the first one to return a
  non-None response).  The challenge method takes environ (the WSGI
  environment), 'status' (the status as set by the downstream
  application), the "app_headers" (headers returned by the
  application), and the "forget_headers" (headers returned by all
  participating IIdentifier plugins whom were asked to "forget" this
  user).

  Our BasicAuthChallengerPlugin takes advantage of the fact that the
  HTTPUnauthorized exception imported from paste.httpexceptions can be
  used as a WSGI application.  It first makes sure that we don't
  repeat headers if an identification plugin has already set a
  "WWW-Authenticate" header like ours, then it returns an instance of
  HTTPUnauthorized, passing in merged headers.  This will cause a
  basic authentication dialog to be presented to the user.

Interfaces

  See the module repoze.pam.interfaces.

