from wsgiref import util as wsgiref_util

import pytest
from zope.interface import exceptions as iface_exc
from zope.interface.verify import verifyClass
from zope.interface.verify import verifyObject

from repoze.who import api as api_module
from repoze.who import interfaces


def _make_wsgi_environ():
    environ = {}
    wsgiref_util.setup_testing_defaults(environ)
    return environ


def test_get_api_w_empty_environ():
    environ = {}

    api = api_module.get_api(environ)

    assert api is None


def test_get_api_w_api_in_environ():
    expected = object()
    environ = {"repoze.who.api": expected}

    api = api_module.get_api(environ)

    assert api is expected


def _make_api_factory(
    plugins=None,
    identifiers=None,
    authenticators=None,
    challengers=None,
    mdproviders=None,
    request_classifier=None,
    challenge_decider=None,
    remote_user_key=None,
    logger=None,
):
    if plugins is None:
        plugins = {}

    if identifiers is None:
        identifiers = ()

    if authenticators is None:
        authenticators = ()

    if challengers is None:
        challengers = ()

    if mdproviders is None:
        mdproviders = ()

    return api_module.APIFactory(
        identifiers,
        authenticators,
        challengers,
        mdproviders,
        request_classifier,
        challenge_decider,
        remote_user_key,
        logger,
    )


def test_api_factory_class_conforms_to_IAPIFactory():
    verifyClass(interfaces.IAPIFactory, api_module.APIFactory)


def test_api_factory_instance_conforms_to_IAPIFactory():
    inst = _make_api_factory()

    verifyObject(interfaces.IAPIFactory, inst)


def test_api_factory_ctor_defaults():
    factory = _make_api_factory()

    assert len(factory.identifiers) == 0
    assert len(factory.authenticators) == 0
    assert len(factory.challengers) == 0
    assert len(factory.mdproviders) == 0
    assert factory.request_classifier is None
    assert factory.challenge_decider is None
    assert factory.logger is None


def test_api_factory___call___empty_environ():
    environ = {}
    factory = _make_api_factory()

    api = factory(environ)

    assert isinstance(api, api_module.API)
    assert environ["repoze.who.api"] is api


def test_api_factory___call___w_api_in_environ():
    expected = object()
    environ = {"repoze.who.api": expected}
    factory = _make_api_factory()

    api = factory(environ)

    assert api is expected


def test_make_registries_w_empty():
    iface_reg, name_reg = api_module.make_registries([], [], [], [])
    assert iface_reg == {}
    assert name_reg == {}


def test_make_registries_w_brokenimpl():
    # BBB for zope.interface < 5.0.0
    expected_exc = (iface_exc.Invalid, ValueError)

    with pytest.raises(expected_exc):
        api_module.make_registries([(None, object())], [], [], [])


def test_make_registries_w_ok():
    credentials1 = {"login": "chris", "password": "password"}
    dummy_id1 = DummyIdentifier(credentials1)
    credentials2 = {"login": "chris", "password": "password"}
    dummy_id2 = DummyIdentifier(credentials2)
    identifiers = [("id1", dummy_id1), ("id2", dummy_id2)]
    dummy_auth = DummyAuthenticator(None)
    authenticators = [("auth", dummy_auth)]
    dummy_challenger = DummyChallenger(None)
    challengers = [("challenger", dummy_challenger)]
    dummy_mdprovider = DummyMDProvider()
    mdproviders = [("mdprovider", dummy_mdprovider)]

    iface_reg, name_reg = api_module.make_registries(
        identifiers,
        authenticators,
        challengers,
        mdproviders,
    )

    assert iface_reg[interfaces.IIdentifier] == [dummy_id1, dummy_id2]
    assert iface_reg[interfaces.IAuthenticator] == [dummy_auth]
    assert iface_reg[interfaces.IChallenger] == [dummy_challenger]
    assert iface_reg[interfaces.IMetadataProvider] == [dummy_mdprovider]
    assert name_reg["id1"] == dummy_id1
    assert name_reg["id2"] == dummy_id2
    assert name_reg["auth"] == dummy_auth
    assert name_reg["challenger"] == dummy_challenger
    assert name_reg["mdprovider"] == dummy_mdprovider


def test_match_classification():
    multi1 = DummyMultiPlugin()
    multi2 = DummyMultiPlugin()
    multi1.classifications = {
        interfaces.IIdentifier: ("foo", "bar"),
        interfaces.IChallenger: ("buz",),
        interfaces.IAuthenticator: None,
    }
    multi2.classifications = {
        interfaces.IIdentifier: ("foo", "baz", "biz"),
    }
    plugins = (multi1, multi2)
    # specific
    assert api_module.match_classification(
        interfaces.IIdentifier,
        plugins,
        "foo",
    ) == [multi1, multi2]
    assert api_module.match_classification(
        interfaces.IIdentifier,
        plugins,
        "bar",
    ) == [multi1]
    assert api_module.match_classification(
        interfaces.IIdentifier,
        plugins,
        "biz",
    ) == [multi2]
    # any for multi2
    assert api_module.match_classification(
        interfaces.IChallenger,
        plugins,
        "buz",
    ) == [multi1, multi2]
    # any for either
    assert api_module.match_classification(
        interfaces.IAuthenticator,
        plugins,
        "buz",
    ) == [multi1, multi2]


def _make_API(
    environ=None,
    identifiers=None,
    authenticators=None,
    challengers=None,
    request_classifier=None,
    mdproviders=None,
    challenge_decider=None,
    remote_user_key=None,
    logger=None,
):
    if environ is None:
        environ = {}

    if identifiers is None:
        identifiers = []

    if authenticators is None:
        authenticators = []

    if challengers is None:
        challengers = []

    if request_classifier is None:
        request_classifier = DummyRequestClassifier()

    if mdproviders is None:
        mdproviders = []

    if challenge_decider is None:
        challenge_decider = DummyChallengeDecider()

    return api_module.API(
        environ,
        identifiers,
        authenticators,
        challengers,
        mdproviders,
        request_classifier,
        challenge_decider,
        remote_user_key,
        logger,
    )


def test_api_class_conforms_to_IAPI():
    verifyClass(interfaces.IAPI, api_module.API)


def test_api_ctor_accepts_logger_instance():
    logger = DummyLogger()
    api = _make_API(logger=logger)

    assert api.logger is logger
    assert len(logger._info) == 1
    assert logger._info[0] == "request classification: browser"
    assert len(logger._debug) == 0


def test_api_authenticate_no_identities():
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    plugin = DummyNoResultsIdentifier()
    plugins = [("dummy", plugin)]
    api = _make_API(environ=environ, identifiers=plugins, logger=logger)

    identity = api.authenticate()

    assert identity is None
    assert len(logger._info) == 2
    assert logger._info[0] == "request classification: browser"
    assert logger._info[1] == "no identities found, not authenticating"


def test_api_authenticate_w_identities_no_authenticators():
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    credentials = {"login": "chris", "password": "password"}
    identifier = DummyIdentifier(credentials)
    identifiers = [("i", identifier)]
    api = _make_API(environ=environ, identifiers=identifiers, logger=logger)

    identity = api.authenticate()

    assert identity is None
    assert len(logger._info) == 2
    assert logger._info[0] == "request classification: browser"
    # Hmm, should this message distinguish "none found" from
    # "none authenticated"?
    assert logger._info[1] == "no identities found, not authenticating"


# def test_authenticate_w_identities_w_authenticators_miss():
def test_api_authenticate_w_identities_w_authenticators_hit():
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    credentials = {"login": "chris", "password": "password"}
    identifier = DummyIdentifier(credentials)
    identifiers = [("i", identifier)]
    authenticator = DummyAuthenticator("chrisid")
    authenticators = [("a", authenticator)]
    api = _make_API(
        environ=environ,
        identifiers=identifiers,
        authenticators=authenticators,
        logger=logger,
    )

    identity = api.authenticate()

    assert identity["repoze.who.userid"] == "chrisid"
    assert identity["identifier"] is identifier
    assert identity["authenticator"] is authenticator

    assert len(logger._info) == 1
    assert logger._info[0] == "request classification: browser"


def test_api_challenge_noidentifier_noapp():
    logger = DummyLogger()
    identity = {"login": "chris", "password": "password"}
    environ = _make_wsgi_environ()
    environ["repoze.who.identity"] = identity
    challenger = DummyChallenger()
    plugins = [("challenge", challenger)]
    api = _make_API(
        environ=environ,
        challengers=plugins,
        request_classifier=lambda environ: "match",
        logger=logger,
    )

    app = api.challenge("401 Unauthorized", [])

    assert app is None
    assert environ["challenged"] is None
    assert len(logger._info) == 2
    assert logger._info[0] == "request classification: match"
    assert logger._info[1] == "no challenge app returned"
    assert len(logger._debug) == 2
    assert logger._debug[0].startswith("challengers registered: [")
    assert logger._debug[1].startswith(
        'challengers matched for classification "match": ['
    )


def test_api_challenge_noidentifier_with_app():
    logger = DummyLogger()
    identity = {"login": "chris", "password": "password"}
    environ = _make_wsgi_environ()
    environ["repoze.who.identity"] = identity
    app = DummyApp()
    challenger = DummyChallenger(app)
    plugins = [("challenge", challenger)]
    api = _make_API(
        environ=environ,
        challengers=plugins,
        request_classifier=lambda environ: "match",
        logger=logger,
    )

    result = api.challenge("401 Unauthorized", [])

    assert result is app
    assert environ["challenged"] is app
    assert len(logger._info) == 2
    assert logger._info[0] == "request classification: match"
    assert logger._info[1].startswith("challenger plugin ")
    assert logger._info[1].endswith('"challenge" returned an app')
    assert len(logger._debug) == 2
    assert logger._debug[0].startswith("challengers registered: [")
    assert logger._debug[1].startswith(
        'challengers matched for classification "match": ['
    )


def test_api_challenge_identifier_no_app_no_forget_headers():
    logger = DummyLogger()
    credentials = {"login": "chris", "password": "password"}
    identifier = DummyIdentifier(credentials)
    identity = {
        "login": "chris",
        "password": "password",
        "identifier": identifier,
    }
    environ = _make_wsgi_environ()
    environ["repoze.who.identity"] = identity
    challenger = DummyChallenger()
    plugins = [("challenge", challenger)]
    api = _make_API(
        environ=environ,
        challengers=plugins,
        request_classifier=lambda environ: "match",
        logger=logger,
    )

    result = api.challenge("401 Unauthorized", [])

    assert result is None
    assert environ["challenged"] is None
    assert identifier.forgotten is identity
    assert len(logger._info) == 3
    assert logger._info[0] == "request classification: match"
    assert logger._info[1].startswith("forgetting via headers ")
    assert logger._info[2] == "no challenge app returned"
    assert len(logger._debug) == 2
    assert logger._debug[0].startswith("challengers registered: [")
    assert logger._debug[1].startswith(
        'challengers matched for classification "match": ['
    )


def test_api_challenge_identifier_app_no_forget_headers():
    logger = DummyLogger()
    credentials = {"login": "chris", "password": "password"}
    identifier = DummyIdentifier(credentials)
    identity = {
        "login": "chris",
        "password": "password",
        "identifier": identifier,
    }
    environ = _make_wsgi_environ()
    environ["repoze.who.identity"] = identity
    app = DummyApp()
    challenger = DummyChallenger(app)
    plugins = [("challenge", challenger)]
    api = _make_API(
        environ=environ,
        challengers=plugins,
        request_classifier=lambda environ: "match",
        logger=logger,
    )

    result = api.challenge("401 Unauthorized", [])

    assert result is app
    assert environ["challenged"] is app
    assert identifier.forgotten is identity
    assert len(logger._info) == 3
    assert logger._info[0] == "request classification: match"
    assert logger._info[1].startswith("forgetting via headers ")
    assert logger._info[2].startswith("challenger plugin ")
    assert logger._info[2].endswith('"challenge" returned an app')
    assert len(logger._debug) == 2
    assert logger._debug[0].startswith("challengers registered: [")
    assert logger._debug[1].startswith(
        'challengers matched for classification "match": ['
    )


def test_api_challenge_identifier_no_app_forget_headers():
    FORGET_HEADERS = [("X-testing-forget", "Oubliez!")]
    logger = DummyLogger()
    credentials = {"login": "chris", "password": "password"}
    identifier = DummyIdentifier(credentials, forget_headers=FORGET_HEADERS)
    identity = {
        "login": "chris",
        "password": "password",
        "identifier": identifier,
    }
    environ = _make_wsgi_environ()
    environ["repoze.who.identity"] = identity
    app = DummyApp()
    challenger = DummyChallenger(app)
    plugins = [("challenge", challenger)]
    api = _make_API(
        environ=environ,
        challengers=plugins,
        request_classifier=lambda environ: "match",
        logger=logger,
    )

    result = api.challenge("401 Unauthorized", [])

    assert result is app
    assert environ["challenged"] is app
    assert challenger._challenged_with[3] == FORGET_HEADERS
    assert len(logger._info) == 3
    assert logger._info[0] == "request classification: match"
    assert logger._info[1].startswith("forgetting via headers from")
    assert logger._info[1].endswith(repr(FORGET_HEADERS))
    assert logger._info[2].startswith("challenger plugin ")
    assert logger._info[2].endswith('"challenge" returned an app')
    assert len(logger._debug) == 2
    assert logger._debug[0].startswith("challengers registered: [")
    assert logger._debug[1].startswith(
        'challengers matched for classification "match": ['
    )


def test_api_challenge_w_multi_challengers_firstwins():
    credentials = {"login": "chris", "password": "password"}
    identifier = DummyIdentifier(credentials)
    identity = {
        "login": "chris",
        "password": "password",
        "identifier": identifier,
    }
    environ = _make_wsgi_environ()
    environ["repoze.who.identity"] = identity
    app1 = DummyApp()
    app2 = DummyApp()
    challenger1 = DummyChallenger(app1)
    challenger2 = DummyChallenger(app2)
    plugins = [("challenge1", challenger1), ("challenge2", challenger2)]
    api = _make_API(
        environ=environ,
        challengers=plugins,
        request_classifier=lambda environ: "match",
    )

    result = api.challenge("401 Unauthorized", [])

    assert result is app1
    assert environ["challenged"] is app1
    assert identifier.forgotten is identity


def test_api_challenge_w_multi_challengers_skipnomatch_findimplicit():
    credentials = {"login": "chris", "password": "password"}
    identifier = DummyIdentifier(credentials)
    identity = {
        "login": "chris",
        "password": "password",
        "identifier": identifier,
    }
    environ = _make_wsgi_environ()
    environ["repoze.who.identity"] = identity
    app1 = DummyApp()
    app2 = DummyApp()
    challenger1 = DummyChallenger(app1)
    challenger1.classifications = {interfaces.IChallenger: ["nomatch"]}
    challenger2 = DummyChallenger(app2)
    challenger2.classifications = {interfaces.IChallenger: None}
    plugins = [("challenge1", challenger1), ("challenge2", challenger2)]
    api = _make_API(
        environ=environ,
        challengers=plugins,
        request_classifier=lambda environ: "match",
    )

    result = api.challenge("401 Unauthorized", [])

    assert result is app2
    assert environ["challenged"] is app2
    assert identifier.forgotten is identity


def test_api_challenge_w_multi_challengers_skipnomatch_findexplicit():
    credentials = {"login": "chris", "password": "password"}
    identifier = DummyIdentifier(credentials)
    identity = {
        "login": "chris",
        "password": "password",
        "identifier": identifier,
    }
    environ = _make_wsgi_environ()
    environ["repoze.who.identity"] = identity
    app1 = DummyApp()
    app2 = DummyApp()
    challenger1 = DummyChallenger(app1)
    challenger1.classifications = {interfaces.IChallenger: ["nomatch"]}
    challenger2 = DummyChallenger(app2)
    challenger2.classifications = {interfaces.IChallenger: ["match"]}
    plugins = [("challenge1", challenger1), ("challenge2", challenger2)]
    api = _make_API(
        environ=environ,
        challengers=plugins,
        request_classifier=lambda environ: "match",
    )

    result = api.challenge("401 Unauthorized", [])

    assert result is app2
    assert environ["challenged"] is app2
    assert identifier.forgotten is identity


def test_api_remember_identifier_plugin_returns_none():
    identity = {"identifier": DummyNoResultsIdentifier()}
    api = _make_API()
    headers = api.remember(identity=identity)
    assert tuple(headers) == ()


def test_api_remember_no_identity_passed_or_in_environ():
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    api = _make_API(environ=environ)
    assert len(api.remember()) == 0
    assert len(logger._info) == 0
    assert len(logger._debug) == 0


def test_api_remember_no_identity_passed_but_in_environ():
    HEADERS = [("Foo", "Bar"), ("Baz", "Qux")]
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    environ["repoze.who.identity"] = {
        "identifier": DummyIdentifier(remember_headers=HEADERS)
    }
    api = _make_API(environ=environ, logger=logger)

    result = api.remember()

    assert result == HEADERS
    assert len(logger._info) == 2
    assert logger._info[0] == "request classification: browser"
    assert logger._info[1].startswith("remembering via headers from")
    assert logger._info[1].endswith(repr(HEADERS))
    assert len(logger._debug) == 0


def test_api_remember_w_identity_passed_no_identifier():
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    api = _make_API(environ=environ, logger=logger)
    identity = {}

    result = api.remember(identity)

    assert len(result) == 0
    assert len(logger._info) == 1
    assert logger._info[0] == "request classification: browser"
    assert len(logger._debug) == 0


def test_api_remember_w_identity_passed_w_identifier():
    HEADERS = [("Foo", "Bar"), ("Baz", "Qux")]
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    api = _make_API(environ=environ, logger=logger)
    identity = {"identifier": DummyIdentifier(remember_headers=HEADERS)}

    result = api.remember(identity)

    assert result == HEADERS
    assert len(logger._info) == 2
    assert logger._info[0] == "request classification: browser"
    assert logger._info[1].startswith("remembering via headers from")
    assert logger._info[1].endswith(repr(HEADERS))
    assert len(logger._debug) == 0


def test_api_forget_identifier_plugin_returns_none():
    identity = {"identifier": DummyNoResultsIdentifier()}
    api = _make_API()

    result = api.forget(identity=identity)

    assert tuple(result) == ()


def test_api_forget_no_identity_passed_or_in_environ():
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    api = _make_API(environ=environ, logger=logger)

    result = api.forget()

    assert len(result) == 0
    assert len(logger._info) == 1
    assert logger._info[0] == "request classification: browser"
    assert len(logger._debug) == 0


def test_api_forget_no_identity_passed_but_in_environ():
    HEADERS = [("Foo", "Bar"), ("Baz", "Qux")]
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    environ["repoze.who.identity"] = {
        "identifier": DummyIdentifier(forget_headers=HEADERS)
    }
    api = _make_API(environ=environ, logger=logger)

    result = api.forget()

    assert result == HEADERS
    assert len(logger._info) == 2
    assert logger._info[0] == "request classification: browser"
    assert logger._info[1].startswith("forgetting via headers from")
    assert logger._info[1].endswith(repr(HEADERS))
    assert len(logger._debug) == 0


def test_api_forget_w_identity_passed_no_identifier():
    environ = _make_wsgi_environ()
    logger = DummyLogger()
    api = _make_API(environ=environ, logger=logger)
    identity = {}

    result = api.forget(identity=identity)

    assert len(result) == 0
    assert len(logger._info) == 1
    assert logger._info[0] == "request classification: browser"
    assert len(logger._debug) == 0


def test_api_forget_w_identity_passed_w_identifier():
    HEADERS = [("Foo", "Bar"), ("Baz", "Qux")]
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    api = _make_API(environ=environ, logger=logger)
    identity = {"identifier": DummyIdentifier(forget_headers=HEADERS)}

    result = api.forget(identity=identity)

    assert result == HEADERS
    assert len(logger._info) == 2
    assert logger._info[0] == "request classification: browser"
    assert logger._info[1].startswith("forgetting via headers from")
    assert logger._info[1].endswith(repr(HEADERS))
    assert len(logger._debug) == 0


def test_api_login_w_identifier_name_hit():
    REMEMBER_HEADERS = [("Foo", "Bar"), ("Baz", "Qux")]
    authenticator = DummyAuthenticator("chrisid")
    environ = _make_wsgi_environ()
    identifiers = [
        ("bogus", DummyNoResultsIdentifier()),
        ("valid", DummyIdentifier(remember_headers=REMEMBER_HEADERS)),
    ]
    api = _make_API(
        identifiers=identifiers,
        authenticators=[("authentic", authenticator)],
        environ=environ,
    )

    identity, headers = api.login({"login": "chrisid"}, "valid")

    assert identity["repoze.who.userid"] == "chrisid"
    assert headers == REMEMBER_HEADERS


def test_api_login_wo_identifier_name_hit():
    REMEMBER_HEADERS = [("Foo", "Bar"), ("Baz", "Qux")]
    authenticator = DummyAuthenticator("chrisid")
    environ = _make_wsgi_environ()
    identifiers = [
        ("bogus", DummyIdentifier(remember_headers=REMEMBER_HEADERS[:1])),
        ("valid", DummyIdentifier(remember_headers=REMEMBER_HEADERS[1:])),
    ]
    api = _make_API(
        identifiers=identifiers,
        authenticators=[("authentic", authenticator)],
        environ=environ,
    )

    identity, headers = api.login({"login": "chrisid"})

    assert identity["repoze.who.userid"] == "chrisid"
    assert headers == REMEMBER_HEADERS


def test_api_login_w_identifier_name_miss():
    REMEMBER_HEADERS = [("Foo", "Bar"), ("Baz", "Qux")]
    FORGET_HEADERS = [("Spam", "Blah")]
    authenticator = DummyFailAuthenticator()
    environ = _make_wsgi_environ()
    identifiers = [
        ("bogus", DummyNoResultsIdentifier()),
        (
            "valid",
            DummyIdentifier(
                remember_headers=REMEMBER_HEADERS,
                forget_headers=FORGET_HEADERS,
            ),
        ),
    ]
    api = _make_API(
        identifiers=identifiers,
        authenticators=[("authentic", authenticator)],
        environ=environ,
    )

    identity, headers = api.login({"login": "notchrisid"}, "valid")

    assert identity is None
    assert headers == FORGET_HEADERS


def test_api_logout_wo_identifier_name_miss():
    FORGET_HEADERS = [("Spam", "Blah")]
    environ = _make_wsgi_environ()
    identifiers = [
        ("valid", DummyIdentifier(forget_headers=FORGET_HEADERS[:1])),
        ("bogus", DummyIdentifier(forget_headers=FORGET_HEADERS[1:])),
    ]
    api = _make_API(identifiers=identifiers, environ=environ)

    headers = api.logout()

    assert headers == FORGET_HEADERS


def test_api_logout_w_identifier_name():
    FORGET_HEADERS = [("Spam", "Blah")]
    environ = _make_wsgi_environ()
    identifiers = [
        ("bogus", DummyNoResultsIdentifier()),
        ("valid", DummyIdentifier(forget_headers=FORGET_HEADERS)),
    ]
    api = _make_API(identifiers=identifiers, environ=environ)

    headers = api.logout("valid")

    assert headers == FORGET_HEADERS


def test_api_logout_wo_identifier_name():
    FORGET_HEADERS = [("Spam", "Blah")]
    authenticator = DummyFailAuthenticator()
    environ = _make_wsgi_environ()
    identifiers = [
        ("bogus", DummyNoResultsIdentifier()),
        ("valid", DummyIdentifier(forget_headers=FORGET_HEADERS)),
    ]
    api = _make_API(
        identifiers=identifiers,
        authenticators=[("authentic", authenticator)],
        environ=environ,
    )

    headers = api.logout()

    assert headers == FORGET_HEADERS


def test_api_logout_removes_repoze_who_identity():
    authenticator = DummyFailAuthenticator()
    environ = _make_wsgi_environ()
    environ["repoze.who.identity"] = "identity"
    identifiers = [("valid", DummyNoResultsIdentifier())]
    api = _make_API(
        identifiers=identifiers,
        authenticators=[("authentic", authenticator)],
        environ=environ,
    )

    api.logout()

    assert "repoze.who.identity" not in environ


def test_api__identify_success():
    environ = _make_wsgi_environ()
    credentials = {"login": "chris", "password": "password"}
    identifier = DummyIdentifier(credentials)
    identifiers = [("i", identifier)]
    api = _make_API(environ=environ, identifiers=identifiers)

    results = api._identify()

    assert len(results) == 1
    new_identifier, identity = results[0]
    assert new_identifier == identifier
    assert identity["login"] == "chris"
    assert identity["password"] == "password"


def test_api__identify_success_empty_identity():
    environ = _make_wsgi_environ()
    identifier = DummyIdentifier({})
    identifiers = [("i", identifier)]
    api = _make_API(environ=environ, identifiers=identifiers)

    results = api._identify()

    assert len(results) == 1
    new_identifier, identity = results[0]
    assert new_identifier == identifier
    assert identity == {}


def test_api__identify_fail():
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    plugin = DummyNoResultsIdentifier()
    plugins = [("dummy", plugin)]
    api = _make_API(environ=environ, identifiers=plugins, logger=logger)

    results = api._identify()

    assert len(results) == 0
    assert len(logger._info) == 1
    assert logger._info[0] == "request classification: browser"
    assert len(logger._debug) == 4
    assert logger._debug[0].startswith("identifier plugins registered: [")
    assert logger._debug[1].startswith(
        'identifier plugins matched for classification "browser": ['
    )
    assert logger._debug[2].startswith("no identity returned from <")
    assert logger._debug[2].endswith("> (None)")
    assert logger._debug[3] == "identities found: []"


def test_api__identify_success_skip_noresults():
    environ = _make_wsgi_environ()
    api = _make_API()
    plugin1 = DummyNoResultsIdentifier()
    credentials = {"login": "chris", "password": "password"}
    plugin2 = DummyIdentifier(credentials)
    plugins = [("identifier1", plugin1), ("identifier2", plugin2)]
    api = _make_API(environ=environ, identifiers=plugins)

    results = api._identify()

    assert len(results) == 1
    new_identifier, identity = results[0]
    assert new_identifier is plugin2
    assert identity["login"] == "chris"
    assert identity["password"] == "password"


def test_api__identify_success_multiresults():
    environ = _make_wsgi_environ()
    api = _make_API()
    plugin1 = DummyIdentifier({"login": "fred", "password": "fred"})
    plugin2 = DummyIdentifier({"login": "bob", "password": "bob"})
    plugins = [("identifier1", plugin1), ("identifier2", plugin2)]
    api = _make_API(environ=environ, identifiers=plugins)

    results = api._identify()

    assert len(results) == 2

    new_identifier, identity = results[0]
    assert new_identifier == plugin1
    assert identity["login"] == "fred"
    assert identity["password"] == "fred"

    new_identifier, identity = results[1]
    assert new_identifier is plugin2
    assert identity["login"] == "bob"
    assert identity["password"] == "bob"


def test_api__identify_find_implicit_classifier():
    environ = _make_wsgi_environ()
    api = _make_API()
    plugin1 = DummyIdentifier({"login": "fred", "password": "fred"})
    plugin1.classifications = {interfaces.IIdentifier: ["nomatch"]}
    plugin2 = DummyIdentifier({"login": "bob", "password": "bob"})
    plugins = [("identifier1", plugin1), ("identifier2", plugin2)]
    api = _make_API(
        environ=environ,
        identifiers=plugins,
        request_classifier=lambda environ: "match",
    )

    results = api._identify()

    assert len(results) == 1
    plugin, creds = results[0]
    assert creds["login"] == "bob"
    assert creds["password"] == "bob"
    assert plugin is plugin2


def test_api__identify_find_explicit_classifier():
    environ = _make_wsgi_environ()
    plugin1 = DummyIdentifier({"login": "fred", "password": "fred"})
    plugin1.classifications = {interfaces.IIdentifier: ["nomatch"]}
    plugin2 = DummyIdentifier({"login": "bob", "password": "bob"})
    plugin2.classifications = {interfaces.IIdentifier: ["match"]}
    plugins = [("identifier1", plugin1), ("identifier2", plugin2)]
    api = _make_API(
        environ=environ,
        identifiers=plugins,
        request_classifier=lambda environ: "match",
    )

    results = api._identify()

    assert len(results) == 1
    plugin, creds = results[0]
    assert creds["login"] == "bob"
    assert creds["password"] == "bob"
    assert plugin is plugin2


def test_api__authenticate_success():
    environ = _make_wsgi_environ()
    plugin1 = DummyAuthenticator("a")
    plugins = [("identifier1", plugin1)]
    api = _make_API(environ=environ, authenticators=plugins)
    identities = [(None, {"login": "chris", "password": "password"})]

    results = api._authenticate(identities)

    assert len(results) == 1
    result = results[0]

    rank, authenticator, identifier, creds, userid = result
    assert rank == (0, 0)
    assert authenticator == plugin1
    assert identifier is None
    assert creds["login"] == "chris"
    assert creds["password"] == "password"
    assert userid == "a"


def test_api__authenticate_fail():
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    # no authenticators
    api = _make_API(environ=environ, logger=logger)
    identities = [(None, {"login": "chris", "password": "password"})]

    result = api._authenticate(identities)

    assert len(result) == 0
    assert len(logger._info) == 1
    assert logger._info[0] == "request classification: browser"
    assert len(logger._debug) == 3
    assert logger._debug[0] == "authenticator plugins registered: []"
    assert logger._debug[1] == (
        'authenticator plugins matched for classification "browser": []'
    )
    assert logger._debug[2] == "identities authenticated: []"


def test_api__authenticate_success_skip_fail():
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    plugin1 = DummyFailAuthenticator()
    plugin2 = DummyAuthenticator()
    plugins = [("dummy1", plugin1), ("dummy2", plugin2)]
    api = _make_API(
        environ=environ,
        authenticators=plugins,
        logger=logger,
    )
    creds = {"login": "chris", "password": "password"}
    identities = [(None, {"login": "chris", "password": "password"})]

    results = api._authenticate(identities)

    assert len(results) == 1
    result = results[0]

    rank, authenticator, identifier, creds, userid = result
    assert rank == (1, 0)
    assert authenticator is plugin2
    assert identifier is None
    assert creds["login"] == "chris"
    assert creds["password"] == "password"
    assert userid == "chris"

    assert len(logger._info) == 1
    assert logger._info[0] == "request classification: browser"
    assert len(logger._debug) == 5
    assert logger._debug[0].startswith("authenticator plugins registered: [")
    assert logger._debug[1].startswith(
        'authenticator plugins matched for classification "browser": ['
    )
    assert logger._debug[2].startswith("no userid returned from")
    assert logger._debug[3].startswith("userid returned from")
    assert logger._debug[3].endswith('"chris"')
    assert logger._debug[4].startswith("identities authenticated: [((1, 0),")


def test_api__authenticate_success_multiresult():
    logger = DummyLogger()
    environ = _make_wsgi_environ()
    plugin1 = DummyAuthenticator("chris_id1")
    plugin2 = DummyAuthenticator("chris_id2")
    plugins = [("dummy1", plugin1), ("dummy2", plugin2)]
    api = _make_API(environ=environ, authenticators=plugins, logger=logger)
    creds = {"login": "chris", "password": "password"}
    identities = [(None, {"login": "chris", "password": "password"})]

    results = api._authenticate(identities)

    assert len(results) == 2
    result = results[0]

    rank, authenticator, identifier, creds, userid = result
    assert rank == (
        0,
        0,
    )
    assert authenticator is plugin1
    assert identifier is None
    assert creds["login"] == "chris"
    assert creds["password"] == "password"
    assert userid == "chris_id1"

    result = results[1]
    rank, authenticator, identifier, creds, userid = result
    assert rank == (1, 0)
    assert authenticator is plugin2
    assert identifier is None
    assert creds["login"] == "chris"
    assert creds["password"] == "password"
    assert userid == "chris_id2"

    assert len(logger._info) == 1
    assert logger._info[0] == "request classification: browser"
    assert len(logger._debug) == 5
    assert logger._debug[0].startswith("authenticator plugins registered: [")
    assert logger._debug[1].startswith(
        'authenticator plugins matched for classification "browser": ['
    )
    assert logger._debug[2].startswith("userid returned from")
    assert logger._debug[2].endswith('"chris_id1"')
    assert logger._debug[3].startswith("userid returned from")
    assert logger._debug[3].endswith('"chris_id2"')
    assert logger._debug[4].startswith("identities authenticated: [((0, 0),")


def test_api__authenticate_find_implicit_classifier():
    environ = _make_wsgi_environ()
    plugin1 = DummyAuthenticator("chris_id1")
    plugin1.classifications = {interfaces.IAuthenticator: ["nomatch"]}
    plugin2 = DummyAuthenticator("chris_id2")
    plugins = [("auth1", plugin1), ("auth2", plugin2)]
    api = _make_API(
        environ=environ,
        authenticators=plugins,
        request_classifier=lambda environ: "match",
    )
    identities = [(None, {"login": "chris", "password": "password"})]

    results = api._authenticate(identities)

    assert len(results) == 1
    result = results[0]

    rank, authenticator, identifier, creds, userid = result
    assert rank == (0, 0)
    assert authenticator is plugin2
    assert identifier is None
    assert creds["login"] == "chris"
    assert creds["password"] == "password"
    assert userid == "chris_id2"


def test_api__authenticate_find_explicit_classifier():
    environ = _make_wsgi_environ()
    plugin1 = DummyAuthenticator("chris_id1")
    plugin1.classifications = {interfaces.IAuthenticator: ["nomatch"]}
    plugin2 = DummyAuthenticator("chris_id2")
    plugin2.classifications = {interfaces.IAuthenticator: ["match"]}
    plugins = [("auth1", plugin1), ("auth2", plugin2)]
    api = _make_API(
        environ=environ,
        authenticators=plugins,
        request_classifier=lambda environ: "match",
    )
    identities = [(None, {"login": "chris", "password": "password"})]

    results = api._authenticate(identities)

    assert len(results) == 1
    result = results[0]

    rank, authenticator, identifier, creds, userid = result
    assert rank == (0, 0)
    assert authenticator is plugin2
    assert identifier is None
    assert creds["login"] == "chris"
    assert creds["password"] == "password"
    assert userid == "chris_id2"


def test_api__authenticate_user_null_but_not_none():
    environ = _make_wsgi_environ()
    plugin1 = DummyAuthenticator(0)
    plugins = [("identifier1", plugin1)]
    api = _make_API(environ=environ, authenticators=plugins)
    identities = [(None, {"login": "chris", "password": "password"})]

    results = api._authenticate(identities)

    assert len(results) == 1
    result = results[0]

    rank, authenticator, identifier, creds, userid = result
    assert rank == (0, 0)
    assert authenticator is plugin1
    assert identifier is None
    assert creds["login"] == "chris"
    assert creds["password"] == "password"
    assert userid == 0


def test_api__add_metadata():
    environ = _make_wsgi_environ()
    plugin1 = DummyMDProvider({"foo": "bar"})
    plugin2 = DummyMDProvider({"fuz": "baz"})
    plugins = [("meta1", plugin1), ("meta2", plugin2)]
    api = _make_API(environ=environ, mdproviders=plugins)
    identity = {}

    api._add_metadata(identity)

    assert identity["foo"] == "bar"
    assert identity["fuz"] == "baz"


def test_api__add_metadata_w_classification():
    environ = _make_wsgi_environ()
    plugin1 = DummyMDProvider({"foo": "bar"})
    plugin2 = DummyMDProvider({"fuz": "baz"})
    plugin2.classifications = {interfaces.IMetadataProvider: ["foo"]}
    plugins = [("meta1", plugin1), ("meta2", plugin2)]
    api = _make_API(environ=environ, mdproviders=plugins)
    identity = {}

    api._add_metadata(identity)

    assert identity["foo"] == "bar"
    assert identity.get("fuz") is None


def test_identity_str():
    identity = api_module.Identity(foo=1)
    assert str(identity).startswith("<repoze.who identity")
    assert identity["foo"] == 1


def test_identity_repr():
    identity = api_module.Identity(foo=1)
    assert str(identity).startswith("<repoze.who identity")
    assert identity["foo"] == 1


class DummyIdentifier:
    forgotten = False
    remembered = False

    def __init__(
        self, credentials=None, remember_headers=(), forget_headers=()
    ):
        self.credentials = credentials
        self.remember_headers = remember_headers
        self.forget_headers = forget_headers

    def identify(self, environ):
        return self.credentials

    def forget(self, environ, identity):
        self.forgotten = identity
        return self.forget_headers

    def remember(self, environ, identity):
        self.remembered = identity
        return self.remember_headers


class DummyNoResultsIdentifier:
    def identify(self, environ):
        return None

    def remember(self, *arg, **kw):
        return ()

    def forget(self, *arg, **kw):
        return ()


class DummyAuthenticator:
    def __init__(self, userid=None):
        self.userid = userid

    def authenticate(self, environ, credentials):
        if self.userid is None:
            return credentials["login"]
        return self.userid


class DummyFailAuthenticator:
    def authenticate(self, environ, credentials):
        return None


class DummyChallenger:
    _challenged_with = None

    def __init__(self, app=None):
        self.app = app

    def challenge(self, environ, status, app_headers, forget_headers):
        environ["challenged"] = self.app
        self._challenged_with = (environ, status, app_headers, forget_headers)
        return self.app


class DummyMDProvider:
    def __init__(self, metadata=None):
        self._metadata = metadata

    def add_metadata(self, environ, identity):
        return identity.update(self._metadata)


class DummyMultiPlugin:
    pass


class DummyRequestClassifier:
    def __call__(self, environ):
        return "browser"


class DummyChallengeDecider:
    pass


class DummyLogger:
    _info = _debug = ()

    def info(self, msg):
        self._info += (msg,)

    def debug(self, msg):
        self._debug += (msg,)


class DummyApp:
    environ = None
