***************************************************
:mod:`repoze.who` -- WSGI Authentication Middleware
***************************************************

:Author: Chris McDonough
:Version: |version|

.. module:: repoze.who
   :synopsis: WSGI authentication middleware

.. topic:: Overview

   ``repoze.who`` is an identification and authentication framework
   for arbitrary WSGI applications.  It acts as WSGI middleware.

   ``repoze.who`` is inspired by Zope 2's Pluggable Authentication
   Service (PAS) (but ``repoze.who`` is not dependent on Zope in any
   way; it is useful for any WSGI application).  It provides no
   facility for authorization (ensuring whether a user can or cannot
   perform the operation implied by the request).  This is considered
   to be the domain of the WSGI application.
 
   It attemtps to reuse implementations from ``paste.auth`` for some
   of its functionality.

Middleware Responsibilities
===========================

``repoze.who`` as middleware has one major function on ingress: it
conditionally places identification and authentication information
(including a ``REMOTE_USER`` value) into the WSGI environment and
allows the request to continue to a downstream WSGI application.

``repoze.who`` as middleware has one major function on egress: it
examines the headers set by the downstream application, the WSGI
environment, or headers supplied by other plugins and conditionally
challenges for credentials.

Configuration Points
====================

Classifiers
-----------

``repoze.who`` "classifies" the request on middleware ingress.
Request classification happens before identification and
authentication.  A request from a browser might be classified a
different way that a request from an XML-RPC client.  ``repoze.who``
uses request classifiers to decide which other components to consult
during subsequent identification, authentication, and challenge steps.
Plugins are free to advertise themselves as willing to participate in
identification and authorization for a request based on this
classification.  The request classification system is pluggable.
``repoze.who`` provides a default classifier that you may use.  You
may extend the classification system by making ``repoze.who`` aware of
a different request classifier implementation.

Challenge Deciders
------------------

``repoze.who`` uses a "challenge decider" to decide whether the
response returned from a downstream application requires a challenge
plugin to fire.  When using the default challenge decider, only the
status is used (if it starts with ``401``, a challenge is required).
You may supply a different challenge decider as necessary.

Plugins
-------

``repoze.who`` has core functionality designed around the concept of
plugins.  Plugins are instances that are willing to perform one or
more identification- and/or authentication-related duties.  Each
plugin can be configured arbitrarily.

``repoze.who`` consults the set of configured plugins when it
intercepts a WSGI request, and gives some subset of them a chance to
influence what ``repoze.who`` does for the current request.

Lifecycle of a Request
======================

``repoze.who`` performs duties both on middleware "ingress" and on
middleware "egress".

Request (Ingress) Stages
------------------------

``repoze.who`` performs the following operations in the following order
during middleware ingress:

1.  Request Classification

    The WSGI environment is examined and the request is classified
    into one "type" of request.  The callable named as the
    ``classifer`` argument to the ``repoze.who`` middleware
    constructor is used to perform the classification.  It returns a
    value that is considered to be the request classification (a
    single string).

2.  Identification

    Identifiers which nominate themselves as willing to extract data
    for a particular class of request (as provided by the request
    classifier) will be consulted to retrieve credentials data from
    the environment.  For example, a basic auth identifier might use
    the ``HTTP_AUTHORIZATION`` header to find login and password
    information.  Identifiers are also responsible for providing
    header information to set and remove authentication information in
    the response during egress.

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

4.  Metadata Provision

    The identity of the authenticated user found during the
    authentication step can be augmented with arbitrary metadata.
    For example, a metadata provider plugin might augment the
    identity with first, middle and last names, or a more
    specialized metadata provider might augment the identity with a
    list of role or group names.

Response (Egress) Stages
------------------------

``repoze.who`` performs the following operations in the following order
during middleware egress:

1.  Challenge Decision

    The WSGI environment and the status and headers returned by the
    downstream application may be examined to determine whether a
    challenge is required.  Typically, only the status is used (if it
    starts with ``401``, a challenge is required, and the challenge
    decider returns True).  This behavior is pluggable.  It is
    replaced by changing the ``challenge_decider`` argument to the
    middleware.  If a challenge is required, the challenge decider
    will return True; if it's not, it will return False.

2.  Challenge

    If the challenge decider returns True, challengers which nominate
    themselves as willing to execute a challenge for a particular
    class of request (as provided by the classifier) will be
    consulted, and one will be chosen to perform a challenge.  A
    challenger plugin can use application-returned headers, the WSGI
    environment, and other items to determine what sort of operation
    should be performed to actuate the challenge.  Note that
    ``repoze.who`` defers to the identifier plugin which provided the
    identity (if any) to reset credentials at challenge time; this is
    not the responsibility of the challenger.  This is known as
    "forgetting" credentials.

3.  Remember

    The identifier plugin that the "best" set of credentials came from
    (if any) will be consulted to "remember" these credentials if the
    challenge decider returns False.

Plugin Types
============

Identifier Plugins
------------------

You can register a plugin as willing to act as an "identifier".  An
identifier examines the WSGI environment and attempts to extract
credentials from the environment.  These credentials are used by
authenticator plugins to perform authentication.  In some cases, an
identification plugin can "preauthenticate" an identity (and can thus
act as an authenticator plugin).

Authenticator Plugins
---------------------

You may register a plugin as willing to act as an "authenticator".
Authenticator plugins are responsible for resolving a set of
credentials provided by an identifier plugin into a user id.
Typically, authenticator plugins will perform a lookup into a database
or some other persistent store, check the provided credentials against
the stored data, and return a user id if the credentials can be
validated.

The user id provided by an authenticator is eventually passed to
downstream WSGI applications in the "REMOTE_USER' environment
variable.  Additionally, the "identity" of the user (as provided by
the identifier from whence the identity came) is passed along to
downstream application in the ``repoze.who.identity`` environment
variable.

Metadata Provider Plugins
-------------------------

You may register a plugin as willing to act as a "metadata provider"
(aka mdprovider).  Metadata provider plugins are responsible for
adding arbitrary information to the identity dictionary for
consumption by downstream applications.  For instance, a metadata
provider plugin may add "group" information to the the identity.

Challenger Plugins
------------------

You may register a plugin as willing to act as a "challenger".
Challenger plugins are responsible for initiating a challenge to the
requesting user.  Challenger plugins are invoked by ``repoze.who`` when it
decides a challenge is necessary. A challenge might consist of
displaying a form or presenting the user with a basic or digest
authentication dialog.

Default Plugin Implementations
==============================

``repoze.who`` ships with a variety of default plugins that do
authentication, identification, challenge and metadata provision.

.. module:: repoze.who.plugins.auth_tkt

.. class:: AuthTktCookiePlugin(secret [, cookie_name='auth_tkt' [, secure=False [, include_ip=False]]])

  An :class:`AuthTktCookiePlugin` is an ``IIdentifier`` plugin which
  remembers its identity state in a client-side cookie.  This plugin
  uses the ``paste.auth.auth_tkt``"auth ticket" protocol.  It should
  be instantiated passing a *secret*, which is used to encrypt the
  cookie on the client side and decrypt the cookie on the server side.
  The cookie name used to store the cookie value can be specified
  using the *cookie_name* parameter.  If *secure* is False, the cookie
  will be sent across any HTTP or HTTPS connection; if it is True, the
  cookie will be sent only across an HTTPS connection.  If
  *include_ip* is True, the ``REMOTE_ADDR`` of the WSGI environment
  will be placed in the cookie.

.. module:: repoze.who.plugins.basicauth

.. class:: BasicAuthPlugin(realm)

  A :class:`BasicAuthPlugin` plugin is both an ``IIdentifier`` and
  ``IChallenger`` plugin that implements the Basic Access
  Authentication scheme described in :rfc:`2617`.  It looks for
  credentials within the ``HTTP-Authorization`` header sent by
  browsers.  It challenges by sending an ``WWW-Authenticate`` header
  to the browser.  The single argument *realm* indicates the basic
  auth realm that should be sent in the ``WWW-Authenticate`` header.

.. module:: repoze.who.plugins.cookie

.. class:: InsecureCookiePlugin(cookie_name)

  A :class:`InsecureCookiePlugin` is an ``IIdentifier`` plugin.  It
  stores identification information in an insecure form (the base64
  value of the username and password separated by a colon) in a
  client-side cookie.  It accepts a single argument named
  *cookie_name*.  This is the cookie name of the cookie used to store
  the identification information.

.. module:: repoze.who.plugins.form

.. class:: FormPlugin(login_form_qs, rememberer_name [, formbody=None [, formcallable=None]])

  A :class:`FormPlugin` is both an ``IIdentifier`` and ``IChallenger``
  plugin.  It intercepts form POSTs to gather identification at
  ingress and conditionally displays a login form at egress if
  challenge is required.  *login_form_qs* is a query string name used
  to denote that a form POST is destined for the form plugin (anything
  unique is fine), *rememberer_name* is the "configuration name" of
  another ``IIdentifier`` plugin that will be used to perform
  ``remember`` and ``forget`` duties for the FormPlugin (it does not
  do these itself).  For example, if you have a cookie identification
  plugin named ``cookie`` defined in your middleware configuration,
  you might set *rememberer_name* to ``cookie``.  *formbody* is a
  literal string that should be displayed as the form body.
  *formcallable* is a callable that will return a form body if
  *formbody* is None.  If both *formbody* and *formcallable* are None,
  a default form is used.

.. class:: RedirectingFormPlugin(login_form_url, login_handler_path, logout_handler_path, rememberer_name)

  A :class:`RedirectingFormPlugin` is both an ``IIdentifier`` and
  ``IChallenger`` plugin.  It intercepts form POSTs to gather
  identification at ingress and conditionally redirects a login form
  at egress if challenge is required (as opposed to the
  :class:`FormPlugin`, it does not handle its own form generation).
  *login_form_url* is a URL that should be redirected to when a
  challnge is required.  *login_handler_path* is the path that the
  form will POST to, signifying that the plugin should gather
  credentials.  *logout_handler_path* is a path that can be called to
  log the current user out when visited. *rememberer_name* is the
  configuration name of another ``IIdentifier`` plugin that will be
  used to perform ``remember`` and ``forget`` duties for the
  RedirectingFormPlugin (it does not do these itself).  For example,
  if you have a cookie identification plugin named ``cookie`` defined
  in your middleware configuration, you might set *rememberer_name* to
  ``cookie``.

.. module:: repoze.who.plugins.htpasswd

.. class:: HTPasswdPlugin(filename, check)

  A :class:`HTPasswdPlugin` is an ``IAuthenticator`` implementation
  which compares identity information against an Apache-style htpasswd
  file.  The *filename* argument should be an absolute path to the
  htpasswd file' the *check* argument is a callable which takes two
  arguments: "password" and "hashed", where the "password" argument is
  the unencrypted password provided by the identifier plugin, and the
  hashed value is the value stored in the htpasswd file.  If the
  hashed value of the password matches the hash, this callable should
  return True.  A default implementation named ``crypt_check`` is
  available for use as a check function (on UNIX) as
  ``repoze.who.plugins.htpasswd:crypt_check``; it assumes the values
  in the htpasswd file are encrypted with the UNIX ``crypt`` function.

.. module:: repoze.who.plugins.sql

.. class:: SQLAuthenticatorPlugin(query, conn_factory, compare_fn)

  A :class:`SQLAuthenticatorPlugin` is an ``IAuthenticator``
  implementation which compares login-password identity information
  against data in an arbitrary SQL database.  The *query* argument
  should be a SQL query that returns two columns in a single row
  considered to be the user id and the password respectively.  The SQL
  query should contain Python-DBAPI style substitution values for
  ``%(login)``, e.g. ``SELECT user_id, password FROM users WHERE login
  = %(login)``.  The *conn_factory* argument should be a callable that
  returns a DBAPI database connection.  The *compare_fn* argument
  should be a callable that accepts two arguments: ``cleartext`` and
  ``stored_password_hash``.  It should compare the hashed version of
  cleartext and return True if it matches the stored password hash,
  otherwise it should return False.  A comparison function named
  ``default_password_compare`` exists in the
  ``repoze.who.plugins.sql`` module demonstrating this.  The
  :class:`SQLAuthenticatorPlugin`\'s ``authenticate`` method will
  return the user id of the user unchanged to ``repoze.who``.

.. class:: SQLMetadataProviderPlugin(name, query, conn_factory, filter)

  A :class:`SQLMetatadaProviderPlugin` is an ``IMetadataProvider``
  implementation which adds arbitrary metadata to the identity on
  ingress using data from an arbitrary SQL database.  The *name*
  argument should be a string.  It will be used as a key in the
  identity dictionary.  The *query* argument should be a SQL query
  that returns arbitrary data from the database in a form that accepts
  Python-binding style DBAPI arguments.  It should expect that a
  ``__userid`` value will exist in the dictionary that is bound.  The
  SQL query should contain Python-DBAPI style substitution values for
  (at least) ``%(__userid)``, e.g. ``SELECT group FROM groups WHERE
  user_id = %(__userid)``.  The *conn_factory* argument should be a
  callable that returns a DBAPI database connection.  The *filter*
  argument should be a callable that accepts the result of the DBAPI
  ``fetchall`` based on the SQL query.  It should massage the data
  into something that will be set in the environment under the *name*
  key.  

Middleware Configuration via Python Code
========================================

.. module:: repoze.who.middleware

.. class:: PluggableAuthenticationMiddleware(app, identifiers, challengers, mdproviders, classifier, challenge_decider [, log_stream=None [, log_level=logging.INFO[, remote_user_key='REMOTE_USER']]])

  The primary method of configuring the ``repoze.who`` middleware is
  to use straight Python code, meant to be consumed by frameworks
  which construct and compose middleware pipelines without using a
  configuration file.

  In the middleware constructor: *app* is the "next" application in
  the WSGI pipeline. *identifiers* is a sequence of ``IIdentifier``
  plugins, *challengers* is a sequence of ``IChallenger`` plugins,
  *mdproviders* is a sequence of ``IMetadataProvider`` plugins.  Any
  of these can be specified as the empty sequence.  *classifier* is a
  request classifier callable, *challenge_decider* is a challenge
  decision callable.  *log_stream* is a stream object (an object with
  a ``write`` method), *log_level* is a numeric value that maps to the
  ``logging`` module's notion of log levels, *remote_user_key* is the
  key in which the ``REMOTE_USER`` (userid) value should be placed in
  the WSGI environment for consumption by downstream applications.

An example configuration which uses the default plugins follows::

    from repoze.who.interfaces import IIdentifier
    from repoze.who.interfaces import IChallenger
    from repoze.who.plugins.basicauth import BasicAuthPlugin
    from repoze.who.plugins.auth_tkt import AuthTktCookiePlugin
    from repoze.who.plugins.cookie import InsecureCookiePlugin
    from repoze.who.plugins.form import FormPlugin
    from repoze.who.plugins.htpasswd import HTPasswdPlugin

    io = StringIO()
    salt = 'aa'
    for name, password in [ ('admin', 'admin'), ('chris', 'chris') ]:
        io.write('%s:%s\n' % (name, password))
    io.seek(0)
    def cleartext_check(password, hashed):
        return password == hashed
    htpasswd = HTPasswdPlugin(io, cleartext_check)
    basicauth = BasicAuthPlugin('repoze.who')
    auth_tkt = AuthTktCookiePlugin('secret', 'auth_tkt')
    form = FormPlugin('__do_login', rememberer_name='auth_tkt')
    form.classifications = { IIdentifier:['browser'],
                             IChallenger:['browser'] } # only for browser
    identifiers = [('form', form),('auth_tkt',auth_tkt),('basicauth',basicauth)]
    authenticators = [('htpasswd', htpasswd)]
    challengers = [('form',form), ('basicauth',basicauth)]
    mdproviders = []

    from repoze.who.classifiers import default_request_classifier
    from repoze.who.classifiers import default_challenge_decider
    log_stream = None
    import os
    if os.environ.get('WHO_LOG'):
        log_stream = sys.stdout

    middleware = PluggableAuthenticationMiddleware(
        app,
        identifiers,
        authenticators,
        challengers,
        mdproviders,
        default_request_classifier,
        default_challenge_decider,
        log_stream = log_stream,
        log_level = logging.DEBUG
        )

    return middleware

The above example configures the repoze.who middleware with:

- Three ``IIdentifier`` plugins (form auth, auth_tkt cookie, and a
  basic auth plugin).  The form auth plugin is set up to fire only
  when the request is a ``browser`` request (as per the combination of
  the request classifier returning ``browser`` and the framework
  checking against the *classifications* attribute of the plugin,
  which limits ``IIdentifier`` and ``IChallenger`` to the ``browser``
  classification only).  In this setup, when "identification" needs to
  be performed, the form auth plugin will be checked first (if the
  request is a browser request), then the auth_tkt cookie plugin, then
  the basic auth plugin.

- One ``IAuthenticator`` plugin: an htpasswd one.  This htpasswd
  plugin is configured with two valid username/password combinations:
  chris/chris, and admin/admin.  When an username and password is
  found via any identifier, it will be checked against this
  authenticator.

- Two ``IChallenger`` plugins: the form plugin, then the basic auth
  plugin.  The form auth will fire if the request is a ``browser``
  request, otherwise the baisc auth plugin will fire.

The rest of the middleware configuration is for values like logging
and the classifier and decider implementations.  These use the "stock"
implementations and values.

Middleware Configuration via Config File
========================================

``repoze.who`` may optionally be configured using a ConfigParser-style
.INI file.  The configuration file has five main types of sections:
plugin sections, a general section, an identifiers section, an
authenticators section, and a challengers section.  Each "plugin"
section defines a configuration for a particular plugin.  The
identifiers, authenticators, and challengers sections refer to these
plugins to form a site configuration.  The general section is general
middleware configuration.

``repoze.who``'s configuration file can be pointed to within a PasteDeploy
configuration file ::

    [filter:who]
    use = egg:repoze.who#config
    config_file = %(here)s/who.ini
    log_file = stdout
    log_level = debug

Below is an example of a configuration file (what ``config_file``
might point at above ) that might be used to configure the
``repoze.who`` middleware.  A set of plugins are defined, and they are
referred to by following non-plugin sections.

In the below configuration, five plugins are defined.  The form, and
basicauth plugins are nominated to act as challenger plugins.  The
form, cookie, and basicauth plugins are nominated to act as
identification plugins.  The htpasswd and sqlusers plugins are
nominated to act as authenticator plugins. ::

    [plugin:form]
    # identificaion and challenge
    use = repoze.who.plugins.form:make_plugin
    login_form_qs = __do_login
    rememberer_name = auth_tkt
    form = %(here)s/login_form.html

    [plugin:auth_tkt]
    # identification
    use = repoze.who.plugins.auth_tkt:make_plugin
    secret = s33kr1t
    cookie_name = oatmeal
    secure = False
    include_ip = False

    [plugin:basicauth]
    # identification and challenge
    use = repoze.who.plugins.basicauth:make_plugin
    realm = 'sample'

    [plugin:htpasswd]
    # authentication
    use = repoze.who.plugins.htpasswd:make_plugin
    filename = %(here)s/passwd
    check_fn = repoze.who.plugins.htpasswd:crypt_check

    [plugin:sqlusers]
    # authentication
    use = repoze.who.plugins.sql:make_authenticator_plugin
    query = "SELECT userid, password FROM users where login = %(login)s;"
    conn_factory = repoze.who.plugins.sql:make_psycopg_conn_factory
    compare_fn = repoze.who.plugins.sql:default_password_compare

    [plugin:sqlproperties]
    name = properties
    use = repoze.who.plugins.sql:make_metadata_plugin
    query = "SELECT firstname, lastname FROM users where userid = %(__userid)s;"
    filter = my.package:filter_propmd
    conn_factory = repoze.who.plugins.sql:make_psycopg_conn_factory

    [general]
    request_classifier = repoze.who.classifiers:default_request_classifier
    challenge_decider = repoze.who.classifiers:default_challenge_decider

    [identifiers]
    # plugin_name;classifier_name:.. or just plugin_name (good for any)
    plugins =
          form;browser
          auth_tkt
          basicauth

    [authenticators]
    # plugin_name;classifier_name.. or just plugin_name (good for any)
    plugins =
          htpasswd
          sqlusers

    [challengers]
    # plugin_name;classifier_name:.. or just plugin_name (good for any)
    plugins =
          form;browser
          basicauth

    [mdproviders]
    plugins =
          sqlproperties

The basicauth section configures a plugin that does identification and
challenge for basic auth credentials.  The form section configures a
plugin that does identification and challenge (its implementation
defers to the cookie plugin for identification "forget" and "remember"
duties, thus the "identifier_impl_name" key; this is looked up at
runtime).  The auth_tkt section configures a plugin that does
identification for cookie auth credentials.  The htpasswd plugin
obtains its user info from a file.  The sqlusers plugin obtains its
user info from a Postgres database.

The identifiers section provides an ordered list of plugins that are
willing to provide identification capability.  These will be consulted
in the defined order.  The tokens on each line of the ``plugins=`` key
are in the form "plugin_name;requestclassifier_name:..."  (or just
"plugin_name" if the plugin can be consulted regardless of the
classification of the request).  The configuration above indicates
that the system will look for credentials using the form plugin (if
the request is classified as a browser request), then the cookie
identifier (unconditionally), then the basic auth plugin
(unconditionally).

The authenticators section provides an ordered list of plugins that
provide authenticator capability.  These will be consulted in the
defined order, so the system will look for users in the file, then in
the sql database when attempting to validate credentials.  No
classification prefixes are given to restrict which of the two plugins
are used, so both plugins are consulted regardless of the
classification of the request.  Each authenticator is called with each
set of identities found by the identifier plugins.  The first identity
that can be authenticated is used to set ``REMOTE_USER``.

The mdproviders section provides an ordered list of plugins that
provide metadata provider capability.  These will be consulted in the
defined order.  Each will have a chance (on ingress) to provide add
metadata to the authenticated identity.  Our example mdproviders
section shows one plugin configured: "sqlproperties".  The
sqlproperties plugin will add information related to user properties
(e.g. first name and last name) to the identity dictionary.

The challengers section provides an ordered list of plugins that
provide challenger capability.  These will be consulted in the defined
order, so the system will consult the cookie auth plugin first, then
the basic auth plugin.  Each will have a chance to initiate a
challenge.  The above configuration indicates that the form challenger
will fire if it's a browser request, and the basic auth challenger
will fire if it's not (fallback).

Writing ``repoze.who`` Plugins
==============================

``repoze.who`` can be extended arbitrarily through the creation of
plugins.  Plugins are of one of four types: identifier plugins,
authenticator plugins, metadata provider plugins, and challenge
plugins.

Writing An Identifier Plugin
----------------------------

An identifier plugin (aka an ``IIdentifier`` plugin) must do three
things: extract credentials from the request and turn them into an
"identity", "remember" credentials, and "forget" credentials.

Here's a simple cookie identification plugin that does these three
things ::

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

.identify
~~~~~~~~~

The ``identify`` method of our InsecureCookiePlugin accepts a single
argument "environ".  This will be the WSGI environment dictionary.
Our plugin attempts to grub through the cookies sent by the client,
trying to find one that matches our cookie name.  If it finds one that
matches, it attempts to decode it and turn it into a login and a
password, which it returns as values in a dictionary.  This dictionary
is thereafter known as an "identity".  If it finds no credentials in
cookies, it returns None (which is not considered an identity).

More generally, the ``identify`` method of an ``IIdentifier`` plugin
is called once on WSGI request "ingress", and it is expected to grub
arbitrarily through the WSGI environment looking for credential
information.  In our above plugin, the credential information is
expected to be in a cookie but credential information could be in a
cookie, a form field, basic/digest auth information, a header, a WSGI
environment variable set by some upstream middleware or whatever else
someone might use to stash authentication information.  If the plugin
finds credentials in the request, it's expected to return an
"identity": this must be a dictionary.  The dictionary is not required
to have any particular keys or value composition, although it's wise
if the identification plugin looks for both a login name and a
password information to return at least {'login':login_name,
'password':password}, as some authenticator plugins may depend on
presence of the names "login" and "password" (e.g. the htpasswd and
sql ``IAuthenticator`` plugins).  If an ``IIdentifier`` plugin finds
no credentials, it is expected to return None.

An ``IIdentifier`` plugin is also permitted to "preauthenticate" an
identity.  If the identifier plugin knows that the identity is "good"
(e.g. in the case of ticket-based authentication where the userid is
embedded into the ticket), it can insert a special key into the
identity dictionary: ``repoze.who.userid``.  If this key is present in
the identity dictionary, no authenticators will be asked to
authenticate the identity.  This effectively allows an ``IIdentifier``
plugin to become an ``IAuthenticator`` plugin when breaking apart the
responsibility into two separate plugins is "make-work".
Preauthenticated identities will be selected first when deciding which
identity to use for any given request.  Our cookie plugin doesn't use
this feature.

.remember
~~~~~~~~~

If we've passed a REMOTE_USER to the WSGI application during ingress
(as a result of providing an identity that could be authenticated),
and the downstream application doesn't kick back with an unauthorized
response, on egress we want the requesting client to "remember" the
identity we provided if there's some way to do that and if he hasn't
already, in order to ensure he will pass it back to us on subsequent
requests without requiring another login.  The remember method of an
``IIdentifier`` plugin is called for each non-unauthenticated
response.  It is the responsibility of the ``IIdentifier`` plugin to
conditionally return HTTP headers that will cause the client to
remember the credentials implied by "identity".
    
Our InsecureCookiePlugin implements the "remember" method by returning
headers which set a cookie if and only if one is not already set with
the same name and value in the WSGI environment.  These headers will
be tacked on to the response headers provided by the downstream
application during the response.

When you write a remember method, most of the work involved is
determining *whether or not* you need to return headers.  It's typical
to see remember methods that compute an "old state" and a "new state"
and compare the two against each other in order to determine if
headers need to be returned.  In our example InsecureCookiePlugin, the
"old state" is ``cookie_value`` and the "new state" is ``value``.

.forget
~~~~~~~

Eventually the WSGI application we're serving will issue a "401
 Unauthorized" or another status signifying that the request could not
 be authorized.  ``repoze.who`` intercepts this status and calls
 ``IIdentifier`` plugins asking them to "forget" the credentials
 implied by the identity.  It is the "forget" method's job at this
 point to return HTTP headers that will effectively clear any
 credentials on the requesting client implied by the "identity"
 argument.

 Our InsecureCookiePlugin implements the "forget" method by returning
 a header which resets the cookie that was set earlier by the remember
 method to one that expires in the past (on my birthday, in fact).
 This header will be tacked onto the response headers provided by the
 downstream application.

Writing an Authenticator Plugin
-------------------------------

An authenticator plugin (aka an ``IAuthenticator`` plugin) must do
only one thing (on "ingress"): accept an identity and check if the
identity is "good".  If the identity is good, it should return a "user
id".  This user id may or may not be the same as the "login" provided
by the user.  An ``IAuthenticator`` plugin will be called for each
identity found during the identification phase (there may be multiple
identities for a single request, as there may be multiple
``IIdentifier`` plugins active at any given time), so it may be called
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

An ``IAuthenticator`` plugin implements one "interface" method:
"authentictate".  The formal specification for the arguments and
return values expected from these methods are available in the
``interfaces.py`` file in ``repoze.who`` as the ``IAuthenticator``
interface, but let's examine this method here less formally.

.authenticate
~~~~~~~~~~~~~

The ``authenticate`` method accepts two arguments: the WSGI
environment and an identity.  Our SimpleHTPasswdPlugin
``authenticate`` implementation grabs the login and password out of
the identity and attempts to find the login in the htpasswd file.  If
it finds it, it compares the crypted version of the password provided
by the user to the crypted version stored in the htpasswd file, and
finally, if they match, it returns the login.  If they do not match,
it returns None.

.. note::

   Our plugin's ``authenticate`` method does not assume that the keys
   ``login`` or ``password`` exist in the identity; although it
   requires them to do "real work" it returns None if they are not
   present instead of raising an exception.  This is required by the
   ``IAuthenticator`` interface specification.

Writing a Challenger Plugin
---------------------------

A challenger plugin (aka an ``IChallenger`` plugin) must do only one
thing on "egress": return a WSGI application which performs a
"challenge".  A WSGI application is a callable that accepts an
"environ" and a "start_response" as its parameters; see "PEP 333" for
further definition of what a WSGI application is.  A challenge asks
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
file in ``repoze.who`` as the ``IChallenger`` interface.  This method
is called when ``repoze.who`` determines that the application has
returned an "unauthorized" response (e.g. a 401).  Only one challenger
will be consulted during "egress" as necessary (the first one to
return a non-None response).

.challenge
~~~~~~~~~~

The challenge method takes environ (the WSGI environment), 'status'
(the status as set by the downstream application), the "app_headers"
(headers returned by the application), and the "forget_headers"
(headers returned by all participating ``IIdentifier`` plugins whom
were asked to "forget" this user).

Our BasicAuthChallengerPlugin takes advantage of the fact that the
HTTPUnauthorized exception imported from paste.httpexceptions can be
used as a WSGI application.  It first makes sure that we don't repeat
headers if an identification plugin has already set a
"WWW-Authenticate" header like ours, then it returns an instance of
HTTPUnauthorized, passing in merged headers.  This will cause a basic
authentication dialog to be presented to the user.

Writing a Metadata Provider Plugin
----------------------------------

A metadata provider plugin (aka an ``IMetadataProvider`` plugin) must
do only one thing (on "ingress"): "scribble" on the identity
dictionary provided to it when it is called.  An ``IMetadataProvider``
plugin will be called with the final "best" identity found during the
authentication phase, or not at all if no "best" identity could be
authenticated.  Thus, each ``IMetadataProvider`` plugin will be called
exactly zero or one times during a request.

Here's a simple metadata provider plugin that provides "property"
information from a dictionary::

    _DATA = {    
        'chris': {'first_name':'Chris', 'last_name':'McDonough'} ,
        'whit': {'first_name':'Whit', 'last_name':'Morriss'} 
        }

    class SimpleMetadataProvider(object):

        def add_metadata(self, environ, identity):
            userid = identity.get('repoze.who.userid')
            info = _DATA.get(userid)
            if info is not None:
                identity.update(info)

.add_metadata
~~~~~~~~~~~~~

Arbitrarily add information to the identity dict based in other data
in the environment or identity.  Our plugin adds ``first_name`` and
``last_name`` values to the identity if the userid matches ``chris``
or ``whit``.

Interfaces
==========

.. module:: repoze.who.interfaces

.. autointerface:: repoze.who.interfaces.IRequestClassifier
   :members:

.. autointerface:: repoze.who.interfaces.IChallengeDecider
   :members:

.. autointerface:: repoze.who.interfaces.IIdentifier
   :members:

.. autointerface:: repoze.who.interfaces.IAuthenticator
   :members:

.. autointerface:: repoze.who.interfaces.IChallenger
   :members:

.. autointerface:: repoze.who.interfaces.IMetadataProvider
   :members:
