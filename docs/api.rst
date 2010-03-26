.. _api_narrative:

Using the :mod:`repoze.who` Application Programming Interface (API)
===================================================================

.. _without_middleware:

Using :mod:`repoze.who` without Middleware
------------------------------------------

An application which does not use the :mod:`repoze.who` middleware needs
to perform two separate tasks to use :mod:`repoze.who` machinery:

- At application startup, it must create an :class:`repoze.who.api:APIFactory`
  instance, populating it with a request classifier, a challenge decider,
  and a set of plugins.  It can do this process imperatively
  (see :ref:`imperative_configuration`), or using a declarative
  configuration file (see :ref:`declarative_configuration`).

- When it needs to use the API, it must call the ``APIFactory``, passing
  the WSGI environment to it.  The ``APIFactory`` returns an object
  implementing the :class:`repoze.who.interfaces:IRepozeWhoAPI` interface.

- Calling the ``APIFactory`` multiple times within the same request is
  allowed, and should be very cheap.


.. _middleware_api_hybrid:

Mixed Use of :mod:`repoze.who` Middleware and API
-------------------------------------------------

An application which uses the :mod:`repoze.who` middleware may still need
to interact directly with the ``IRepozeWhoAPI`` object for some purposes.
In such cases, it should call :func:`repoze.who.api:get_api`, passing
the WSGI environment.

.. _interfaces:

Interfaces
----------

.. automodule:: repoze.who.interfaces

  .. autointerface:: IAPIFactory
     :members:

  .. autointerface:: IAPI
     :members:

  .. autointerface:: IPlugin
     :members:

  .. autointerface:: IRequestClassifier
     :members:

  .. autointerface:: IChallengeDecider
      :members:

  .. autointerface:: IIdentifier
     :members:

  .. autointerface:: IAuthenticator
     :members:

  .. autointerface:: IChallenger
     :members:

  .. autointerface:: IMetadataProvider
     :members:
