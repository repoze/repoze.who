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
 
  It attemtps to reuse implementations from AuthKit and paste.auth for
  some of its functionality.

Middleware Responsibilities

  repoze.pam's middleware has one major function on ingress: it
  conditionally places identification and authentication information
  (including a REMOTE_USER value) into the WSGI environment and allows
  the request to continue to a downstream WSGI application.

  repoze.pam's middleware has one major function on egress: it
  examines the headers set by the downstream application or the WSGI
  environment and conditionally challenges for credentials.

PasteDeploy Configuration

  repoze.pam is designed to be used within a PasteDeploy configuration
  file:

    [filter:pam]
    use = egg:repoze.pam#pam
    config_file = %(here)s/pam.ini

Classifiers

  repoze.pam "classifies" both the request (on middleware ingress) and
  the response (on middleware egress).

  Request classification happens on middleware ingress, before
  extraction and authentication.  A request from a browser might be
  classified a different way that a request from an XML-RPC client.
  repoze.pam uses request classifiers to decide which other components
  to consult during subsequent identification and authentication,
  steps.  Extraction and authenticator plugins are free to advertise
  themselves as willing to participate in identification and
  authorization for a request based on this classification.

  Response classification happens on middleware egress, before
  challenge.  A response from a an application can be classified
  arbitrarily.  repoze.pam uses response classifiers to decide which
  challenge plugins are willing to examine the response, and
  potentially actuate a challenge.  Challenge plugins are free to
  advertise themselves as willing to participate based on the response
  classification.

  The classification system is pluggable.  repoze.pam provides a set
  of default classifiers that you may use.  You may extend the
  classification system by making repoze.pam aware of different
  classifier implementations.

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

Ingress Stages

  repoze.pam performs the following operations in the following order
  during request ingress:

  1.  Request Classification

      The WSGI environment is examined and the request is classified
      into one "type" of request.  The callable named as
      'request_classifer=' within the '[classifiers]' section is used
      to perform the classification.  It returns a value that is
      considered to be the request classification.

  2.  Extraction

      Extractors which nominate themselves as willing to extract data
      for a particular class of request (as provided by the request
      classifier) will be consulted to retrieve login and password
      data from the environment.  For example, a basic auth extractor
      might use the WWW-Authenticate header to find login and password
      information.

  3.  Authentication

      Authenticators which nominate themselves as willing to
      authenticate for a particular class of request will be consulted
      to compare login and password information provided by the
      extraction plugin that returned a set of credentials.  For
      example, an htpasswd authenticator might look in a file for a
      user record matching the login.  If it finds one, and if the
      password listed in the record matches the password found by the
      extractor, the userid of the user would be returned (which would
      be the same as the login name).

Egress Stages

  repoze.pam performs the following operations in the following order
  during request egress:

  1.  Response Classification

      The WSGI environment and the headers returned by the downstream
      application are examined and the request is classified into one
      "type" of request.  The callable named as 'response_classifer='
      within the '[classifiers]' section is used to perform the
      classification.  It returns a value that is considered the
      classification.

  2.  Challenge

      Challengers which nominate themselves as willing to execute a
      challenge for a particular class of request (as provided by the
      response classifier) will be consulted.  The challenger plugins
      can use application-returned headers and the WSGI environment to
      determine what sort of operation should be performed to actuate
      the challenge.  For example, if the application sets a 401
      Unauthorized header in the response headers, a challenge plugin
      might redirect the user to a login page by setting additional
      headers in the response headers.

Plugin Types

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
  configuration file has four main types of sections: plugin sections,
  an authenticators section, a challengers section, and an extractors
  section.  Each "plugin" section defines a configuration for a
  particular plugin.  The classifiers, authenticators, and extractors
  sections refer to these plugins to form a site configuration.

Example repoze.pam Configuration File

  Below is an example of a configuration file that might be used to
  configure the repoze.pam middleware.  A set of plugins are defined,
  and they are referred to by following non-plugin sections.

  In the below configuration, four plugins are defined.  The
  cookieauth and basicauth plugins are nominated to act as both
  challenger and extractor plugins.  The filusers and sqlusers plugins
  are nominated to act as authenticator plugins.

    [plugin:basicauth]
    # challenge and extraction
    use = egg:repoze.pam#basicauth
    # challenge
    realm = repoze

    [plugin:cookieauth]
    # challenge and extraction
    use = egg:repoze.pam#cookieauth
    login_path = /login_form
    cookie_name = repoze.pam.auth
    form_name_name = __ac_name
    form_password_name = __ac_password

    [plugin:fileusers]
    # authentication
    use = egg:repoze.pam#fileusersource
    filename = %(here)s/users.txt
    encryptpwd = egg:repoze.pam#shaencrypt

    [plugin:sqlusers]
    # authentication
    use = egg:repoze.pam#squsersource
    db = sqlite://database?user=foo&pass=bar
    get_userinfo = select id, password from users
    encryptpwd = egg:repoze.pam#shaencrypt

    [classifiers]
    request_classifier = egg:repoze.pam#defaultrequestclassifier
    response_classifier = egg:repoze.pam#defaultresponseclassifier

    [extractors]
    # plugin_name:ingressclassifier_name:.. or just plugin_name (good for any)
    plugins =
          cookieauth:browser
          basicauth

    [authenticators]
    # plugin_name (ingress classifiers ignored)
    plugins =
          fileusers
          sqlusers

    [challengers]
    # plugin_name:egressclassifier_name:.. or just plugin_name (good for any)
    plugins =
          cookieauth:browser
          basicauth

Further Description of Example Config

  The basicauth section configures a plugin that does extraction and
  challenge for basic auth credentials.  The cookieauth section
  configures a plugin that does extraction and challenge for cookie
  auth credentials.  The fileusers plugin obtains its user info from a
  file.  The sqlusers plugin obtains its user info from a sqlite
  database.

  The extractors section provides an ordered list of plugins that are
  willing to provide extraction capability.  These will be consulted
  in the defined order.  The tokens on each line of the plugin= key
  are in the form "plugin_name:classifier" (or just "plugin_name" if
  the plugin can be consulted regardless of the classification of the
  request).  The configuration above indicates that the system will
  look for credentials using the cookie auth plugin (if the request is
  classified as a browser request), then the basic auth plugin
  (unconditionally).

  The authenticators section provides an ordered list of plugins that
  provide authenticator capability.  These will be consulted in the
  defined order, so the system will look for users in the file, then
  in the sql database when attempting to validate credentials.  No
  classification prefixes are given to restrict which of the two
  plugins are used, so both plugins are consulted regardless of the
  classification of the request.

  The challengers section provides an ordered list of plugins that
  provide challenger capability.  These will be consulted in the
  defined order, so the system will consult the cookie auth plugin
  first, then the basic auth plugin.  Each will have a chance, based
  on the request, to initiate a challenge.

Interfaces

  The following interfaces are expected to be provided by plugins
  which the configuration asserts they're willing to provide::

    XXX see interfaces.py
