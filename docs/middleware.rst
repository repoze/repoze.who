.. _using_middleware:

Using :mod:`repoze.who` Middleware
==================================

.. _middleware_responsibilities:

Middleware Responsibilities
---------------------------

:mod:`repoze.who` as middleware has one major function on ingress: it
conditionally places identification and authentication information
(including a ``REMOTE_USER`` value) into the WSGI environment and
allows the request to continue to a downstream WSGI application.

:mod:`repoze.who` as middleware has one major function on egress: it
examines the headers set by the downstream application, the WSGI
environment, or headers supplied by other plugins and conditionally
challenges for credentials.


.. _request_lifecycle:

Lifecycle of a Request
----------------------

:mod:`repoze.who` performs duties both on middleware "ingress" and on
middleware "egress". The following graphic outlines where it sits in the context
of the request and its response:

.. image:: .static/request-lifecycle.png


.. _ingress_stages:

Request (Ingress) Stages
++++++++++++++++++++++++

.. image:: .static/ingress.png

:mod:`repoze.who` performs the following operations in the following
order during middleware ingress:

1.  Request Classification

    The WSGI environment is examined and the request is classified
    into one "type" of request.  The callable named as the
    ``classifer`` argument to the :mod:`repoze.who` middleware
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


.. _egress_stages:

Response (Egress) Stages
++++++++++++++++++++++++

:mod:`repoze.who` performs the following operations in the following
order during middleware egress:

#.  Challenge Decision

    The WSGI environment and the status and headers returned by the
    downstream application may be examined to determine whether a
    challenge is required.  Typically, only the status is used (if it
    starts with ``401``, a challenge is required, and the challenge
    decider returns True).  This behavior is pluggable.  It is
    replaced by changing the ``challenge_decider`` argument to the
    middleware.  If a challenge is required, the challenge decider
    will return True; if it's not, it will return False.

#.  Challenge

    If the challenge decider returns True, challengers which nominate
    themselves as willing to execute a challenge for a particular
    class of request (as provided by the classifier) will be
    consulted, and one will be chosen to perform a challenge.  A
    challenger plugin can use application-returned headers, the WSGI
    environment, and other items to determine what sort of operation
    should be performed to actuate the challenge.  Note that
    :mod:`repoze.who` defers to the identifier plugin which provided the
    identity (if any) to reset credentials at challenge time; this is
    not the responsibility of the challenger.  This is known as
    "forgetting" credentials.

#.  Remember

    The identifier plugin that the "best" set of credentials came from
    (if any) will be consulted to "remember" these credentials if the
    challenge decider returns False.
