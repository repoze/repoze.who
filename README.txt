repoze.pam

Overview

  repoze.pam (Pluggable Authentication Middleware) is an
  identification and authentication framework for WSGI. 

Description

  repoze.pam's ideas are largely culled from Zope 2's Pluggable
  Authentication Service (PAS) (but it is not dependent on Zope).
  Unlike PAS, it provides no facilities for creating user objects,
  assigning roles or groups to users, retrieving or changing user
  properties, or enumerating users, groups, or roles.  These
  responsibilities are assumed to be the domain of the WSGI
  application you're serving.  It also provides no facility for
  authorization (ensuring whether a user can or cannot perform the
  operation implied by the request).  This is also the domain of the
  WSGI application.
 
  It attemtps to reuse implementations from AuthKit for some of its
  functionality.

Middleware Responsibilities

  repoze.pam's middleware has one major function on ingress: it
  conditionally places identification and authorization information
  (including a REMOTE_USER value) into the WSGI environment and allows
  the request to continue to a downstream WSGI application.

  repoze.pam's middleware has one major function on egress: it
  examines the WSGI environment (or catches an exception) and
  conditionally challenges for credentials.

PasteDeploy Configuration

  repoze.pam is designed to be used within a PasteDeploy configuration
  file:

    [filter:pam]
    use = egg:repoze.pam#pam
    config_file = %(here)s/pam.ini

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

Plugin Types

  Classification Plugins

    repoze.pam "classifies" each request.  For example, a request from
    a browser might be classified a different way that a request from
    an XML-RPC client.  repoze.pam uses request classifiers to decide
    which other components to consult during subsequent identification
    and authorization steps.  Other components advertise themselves as
    willing to participate in identification and authorization for a
    request based on this classification.

    The classification system is pluggable.  repoze.pam provides a
    number of default classifiers that you may use.  You may extend
    the classification system by making repoze.pam aware of new
    classifier implementations.

  Extractor Plugins

    You can register a plugin as willing to act as an "extractor".  An
    extractor examines the WSGI environment and attempts to extract
    credentials from the environment.  These credentials are used by
    authenticator plugins to perform authentication.  These
    credentials are conditionally placed into the WSGI environment for
    consumption by downstream applications, as well.

  Authenticator Plugins

    You may register a plugin as willing to act as an "authenticator".
    Authenticator plugins are responsible for resolving a set of
    credentials to a user id.  Typically, authenticator plugins will
    perform a lookup into a database or some other persistent store,
    check the provided credentials against the stored data, and return
    a user id if the credentials can be validated.

    The user id found by repoze.pam is eventually passed to downstream
    WSGI applications in the "REMOTE_USER' environment variable.

  Challenger Plugins

    You may register a plugin as willing to act as an "challenger".
    Challenger plugins are responsible for initiating a challeng" to
    the requesting user.  Challenger plugins catch specific exceptions
    raised by downstream applications and tun the exception into a
    challenge, which might consist of displaying a form or presenting
    the user with a basic or digest authentication dialog.

Configuration File Example

  repoze.pam is configured using a ConfigParser-style .INI file.  The
  configuration file has five main types of sections: plugin sections,
  a classifiers section, an authenticators section, a challengers
  section, and an extractors section.  Each "plugin" section defines a
  configuration for a particular plugin.  The classifiers,
  authenticators, challengers, and extractors sections refer to these
  plugins to form a site configuration.

Example repoze.pam Configuration File

  Below is an example of a configuration file that might be used to
  configure the repoze.pam middleware.  A set of plugins are defined,
  and they are referred to by following non-plugin sections.

  In the below configuration, seven plugins are defined.  The
  cookieauth and basicauth plugins are nominated to act as both
  challenger and extractor plugins.  The filusers and sqlusers plugins
  are nominated to act as authenticator plugins.  The browser, dav,
  and xmlrpc plugins are nominated to act as classifier plugins::

    [plugin:basicauth]
    use = egg:repoze.pam#basicauth
    # challenge
    realm = repoze
    requests = 
        browser
        dav
        xmrpc

    [plugin:cookieauth]
    # extraction, challenge, credentials update, credentials reset
    use = egg:repoze.pam#cookieauth
    # challenge
    requests = browser
    login_path = /login_form
    # extraction
    cookie_name = repoze.pam.auth
    form_name_name = __ac_name
    form_password_name = __ac_password

    [plugin:fileusers]
    use = egg:repoze.pam#fileusersource
    # authentication
    filename = %(here)s/users.txt
    encryptpwd = egg:repoze.pam#shaencrypt

    [plugin:sqlusers]
    use = egg:repoze.pam#squsersource
    # authentication
    db = sqlite://database?user=foo&pass=bar
    get_userinfo = select id, password from users
    encryptpwd = egg:repoze.pam#shaencrypt

    [plugin:browser]
    use = egg:repoze.pam#browserchooser

    [plugin:dav]
    dav = egg:repoze.pam#davchooser

    [plugin:xmlrpc]
    xmlrpc = egg:repoze.pam#xmlrpcchooser

    [classifiers]
    plugins =
          browser
          dav
          xmlrpc

    [extractors]
    plugins =
          cookieauth
          basicauth

    [authenticators]
    plugins =
          fileusers 
          sqlusers

    [challengers]
    plugins =
          cookieauth
          basicauth

Further Description of Example Config

  The basicauth plugin configuration nominates itself as willing to
  participate in requests classified as "browser", "dav", and "xmlrpc"
  (via the "requests" key).  The cookieauth plugin configuration
  nominates itself as willing to participate in requests classified as
  "browser".

  The fileusers plugin obtains its user info from a file.  The
  sqlusers plugin obtains its user info from a sqlite database.

  The classifiers section indicates that the classifiers named in the
  plugins = line each has a chance to classify the request.

  The extractors seciton provides an ordered list of plugins that are
  willing to provide extraction capability.  These will be consulted
  in the defined order, so the system will look for credentials using
  the cookie auth plugin, then the basic auth plugin. 

  The authenticators section provides an ordered list of plugins that
  provide authenticator capability.  These will be consulted in the
  defined order, so the system will look for users in the file, then
  in the sql database when attempting to validate credentials.

  The challengers section provides an ordered list of plugins that
  provide challenger capability.  These will be consulted in the
  defined order, so the system will consult the cookie auth plugin
  first, then the basic auth plugin.  Each will have a chance, based
  on the request, to initiate a challenge.

Interfaces

  The following interfaces are expected to be provided by plugins
  which the configuration asserts they're willing to provide::

    XXX see interfaces.py
