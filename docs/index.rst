.. _index:

***************************************************
:mod:`repoze.who` -- WSGI Authentication Middleware
***************************************************

:Author: Chris McDonough / Tres Seaver
:Version: |version|

.. module:: repoze.who
   :synopsis: WSGI authentication middleware

.. topic:: Overview

   :mod:`repoze.who` is an identification and authentication framework
   for arbitrary WSGI applications.  It acts as WSGI middleware.

   :mod:`repoze.who` is inspired by Zope 2's Pluggable Authentication
   Service (PAS) (but :mod:`repoze.who` is not dependent on Zope in any
   way; it is useful for any WSGI application).  It provides no
   facility for authorization (ensuring whether a user can or cannot
   perform the operation implied by the request).  This is considered
   to be the domain of the WSGI application.
 
   It attempts to reuse implementations from ``paste.auth`` for some
   of its functionality.

Sections
========

.. toctree::
   :maxdepth: 2

   narr
   use_cases
   middleware
   api
   configuration
   plugins

Change History
==============

.. toctree::
   :maxdepth: 2

   changes

Support and Development
=======================

To report bugs, use the `Repoze bug tracker <http://bugs.repoze.org>`_.

If you've got questions that aren't answered by this documentation,
contact the `Repoze-dev maillist
<http://lists.repoze.org/listinfo/repoze-dev>`_ or join the `#repoze
IRC channel <irc://irc.freenode.net/#repoze>`_.

Browse and check out tagged and trunk versions of :mod:`repoze.who`
via the `Repoze Subversion repository
<http://http://svn.repoze.org/repoze.who/>`_.  To check out the trunk
via Subversion, use this command::

  svn co http://svn.repoze.org/repoze.who/trunk repoze.who

To find out how to become a contributor to :mod:`repoze.who`, please
see the `contributor's page <http://repoze.org/contributing.html>`_.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

