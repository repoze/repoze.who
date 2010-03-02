``repoze.who`` -- WSGI Authentication Middleware / API
======================================================

Overview
--------

``repoze.who`` is an identification and authentication framework
for arbitrary WSGI applications.  ``repoze.who`` can be configured
either as WSGI middleware or as an API for use by an application.

``repoze.who`` is inspired by Zope 2's Pluggable Authentication
Service (PAS) (but ``repoze.who`` is not dependent on Zope in any
way; it is useful for any WSGI application).  It provides no facility
for authorization (ensuring whether a user can or cannot perform the
operation implied by the request).  This is considered to be the
domain of the WSGI application.
 
See the ``docs`` subdirectory of this package (also available at least
provisionally at http://static.repoze.org/whodocs) for more
information.
