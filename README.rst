repoze.who
==========

.. image:: https://travis-ci.org/repoze/repoze.who.png?branch=master
        :target: https://travis-ci.org/repoze/repoze.who

.. image:: https://readthedocs.org/projects/repozewho/badge/?version=latest
        :target: http://repozewho.readthedocs.org/en/latest/
        :alt: Documentation Status

.. image:: https://img.shields.io/pypi/v/repoze.who.svg
        :target: https://pypi.python.org/pypi/repoze.who

.. image:: https://img.shields.io/pypi/pyversions/repoze.who.svg
        :target: https://pypi.python.org/pypi/repoze.who

``repoze.who`` is an identification and authentication framework
for arbitrary WSGI applications.  ``repoze.who`` can be configured
either as WSGI middleware or as an API for use by an application.

``repoze.who`` is inspired by Zope 2's Pluggable Authentication
Service (PAS) (but ``repoze.who`` is not dependent on Zope in any
way; it is useful for any WSGI application).  It provides no facility
for authorization (ensuring whether a user can or cannot perform the
operation implied by the request).  This is considered to be the
domain of the WSGI application.

Installation
------------

Install using setuptools, e.g. (within a virtualenv)::

 $ easy_install repoze.who

or using pip::

 $ pip install repoze.who


Usage
-----

For details on using the various components, please see the
documentation in ``docs/index.rst``.  A rendered version of that documentation
is also available online:

 - http://repozewho.readthedocs.org/en/latest/


Reporting Bugs 
--------------

Please report bugs in this package to

  https://github.com/repoze/repoze.who/issues


Obtaining Source Code
---------------------

Download development or tagged versions of the software by visiting:

  https://github.com/repoze/repoze.who

