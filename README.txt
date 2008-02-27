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
 
  It attemtps to reuse implementations from AuthKit and paste.auth for
  some of its functionality.  XXX this is, so far, untrue

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
      classifier) will be consulted to retrieve login and password
      data from the environment.  For example, a basic auth identifier
      might use the HTTP_AUTHORIZATION header to find login and
      password information.  Identifiers are also responsible for
      providing header information to set and remove authentication
      information in the response.

  3.  Authentication

      Authenticators which nominate themselves as willing to
      authenticate for a particular class of request will be consulted
      to compare login and password information provided by the
      identification plugins that returned credentials.  For example,
      an htpasswd authenticator might look in a file for a user record
      matching any of the identities.  If it finds one, and if the
      password listed in the record matches the password provided by
      an identity, the userid of the user would be returned (which
      would be the same as the login name).

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
    used by authenticator plugins to perform authentication.

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

Interfaces

   See repoze.pam.interfaces.

