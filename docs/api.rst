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

.. code-block:: python

   # myapp/run.py
   from repoze.who.api import APIFactory
   def startup(global_conf):
       global who_api_factory

       parser = WhoConfig(global_conf['here'])
       parser.parse(open(global_conf['who_config']))

       who_api_factory = APIFactory(
                            parser.identifiers,
                            parser.authenticators,
                            parser.challengers,
                            parser.mdproviders,
                            parser.request_classifier,
                            parser.challenge_decider,
                            parser.remote_user_key,
                          )

- When it needs to use the API, it must call the ``APIFactory``, passing
  the WSGI environment to it.  The ``APIFactory`` returns an object
  implementing the :class:`repoze.who.interfaces:IRepozeWhoAPI` interface.

.. code-block:: python

   # myapp/views.py
   from myapp.run import who_api_factory
   def my_view(context, request):
       who_api = who_api_factory(request.environ)

- Calling the ``APIFactory`` multiple times within the same request is
  allowed, and should be very cheap (the API object is cached in the
  request environment).


.. _middleware_api_hybrid:

Mixed Use of :mod:`repoze.who` Middleware and API
-------------------------------------------------

An application which uses the :mod:`repoze.who` middleware may still need
to interact directly with the ``IRepozeWhoAPI`` object for some purposes.
In such cases, it should call :func:`repoze.who.api:get_api`, passing
the WSGI environment.

.. code-block:: python

   from repoze.who.api import get_api
   def my_view(context, request):
       who_api = get_api(request.environ)

Alternately, the application might configure the ``APIFactory`` at startup,
as above, and then use it to find the API object, or create it if it was
not already created for the current request (e.g. perhaps by the middleware):

.. code-block:: python

   def my_view(context, request):
       who_api = context.who_api_factory(request.environ)


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
