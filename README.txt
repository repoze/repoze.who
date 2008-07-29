***************************************************
:mod:`repoze.who` -- WSGI Authentication Middleware
***************************************************

:mod:`repoze.who` is an identification and authentication framework
for arbitrary WSGI applications.  It acts as WSGI middleware.

:mod:`repoze.who` is inspired by Zope 2's Pluggable Authentication
Service (PAS) (but :mod:`repoze.who` is not dependent on Zope in any
way; it is useful for any WSGI application).  It provides no facility
for authorization (ensuring whether a user can or cannot perform the
operation implied by the request).  This is considered to be the
domain of the WSGI application.
 
See the ``docs`` subdirectory of this package (also available at least
provisionally at http://static.repoze.org/whodocs) for more
information.

