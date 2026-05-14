from unittest import mock

from repoze.who import restrict


def test_auth_pred__call___no_identity_returns_False():
    predicate = restrict.authenticated_predicate()
    environ = {}

    result = predicate(environ)

    assert not result


def test_auth_pred__call___w_REMOTE_AUTH_returns_True():
    predicate = restrict.authenticated_predicate()
    environ = {'REMOTE_USER': 'fred'}

    result = predicate(environ)

    assert result


def test_auth_pred__call___w_repoze_who_identity_returns_True():
    predicate = restrict.authenticated_predicate()
    environ = {'repoze.who.identity': {'login': 'fred'}}

    result = predicate(environ)

    assert result


def test_make_auth_restriction_enabled():
    app = DummyApp()
    global_config = {"testing": True}

    filter = restrict.make_authenticated_restriction(
        app,
        global_config,
        enabled=True,
    )

    assert filter.app is app
    assert filter.enabled


def test_make_auth_restriction_predicate_miss():
    app = DummyApp()
    global_config = {"testing": True}
    environ = {}

    filter = restrict.make_authenticated_restriction(
        app,
        global_config,
        enabled=True,
    )

    predicate = filter.predicate

    assert not predicate(environ)


def test_make_auth_restriction_predicate_hit_w_remote_user():
    app = DummyApp()
    global_config = {"testing": True}
    environ = {'REMOTE_USER': 'fred'}
    filter = restrict.make_authenticated_restriction(
        app,
        global_config,
        enabled=True,
    )

    predicate = filter.predicate

    assert predicate(environ)


def test_make_auth_restriction_predicate_hit_w_repoze_who_identity():
    app = DummyApp()
    global_config = {"testing": True}
    environ = {'repoze.who.identity': {'login': 'fred'}}
    filter = restrict.make_authenticated_restriction(
        app,
        global_config,
        enabled=True,
    )

    predicate = filter.predicate

    assert predicate(environ)


def test_pred_restriction_w_disabled_predicate_false_calls_app_not_predicate():
    app = DummyApp()
    environ = {'testing': True}

    predicate = mock.Mock(spec_set=())
    factory = mock.Mock(spec_set=(), return_value=predicate)
    start_response = mock.Mock(spec_set=(), side_effect=AssertionError)

    pr = restrict.PredicateRestriction(
        app=app, predicate=factory, enabled=False,
    )
    pr(environ, start_response)

    assert pr.app.environ == environ

    predicate.assert_not_called()
    start_response.assert_not_called()


def test_pred_restriction_w_enabled_predicate_false_returns_401():
    app = DummyApp()
    environ = {'testing': True}

    predicate = mock.Mock(spec_set=(), return_value=False)
    factory = mock.Mock(spec_set=(), return_value=predicate)
    start_response = mock.Mock(spec_set=())

    pr = restrict.PredicateRestriction(app=app, predicate=factory)
    pr(environ, start_response)

    predicate.assert_called_once_with(environ)
    start_response.assert_called_once_with("401 Unauthorized", [])
    assert pr.app.environ is None


def test_pred_restriction_w_enabled_predicate_true_calls_app():
    app = DummyApp()
    environ = {'testing': True, 'REMOTE_USER': 'fred'}

    predicate = mock.Mock(spec_set=(), return_value=True)
    factory = mock.Mock(spec_set=(), return_value=predicate)
    start_response = mock.Mock(spec_set=(), side_effect=AssertionError)

    pr = restrict.PredicateRestriction(app=app, predicate=factory)
    pr(environ, start_response)

    predicate.assert_called_once_with(environ)
    start_response.assert_not_called()
    assert pr.app.environ == environ


def test_make_predicate_restriction_w_non_string_predicate_no_args():
    app = DummyApp()
    global_config = {"testing": True}
    predicate = mock.Mock(spec_set=(), return_value=True)
    factory = mock.Mock(spec_set=(), return_value=predicate)

    filter = restrict.make_predicate_restriction(
        app,
        global_config,
        predicate=factory,
    )

    assert filter.app is app
    assert filter.predicate is predicate
    assert filter.enabled


def test_make_predicate_restriction_w_disabled_non_string_predicate_w_args():
    app = DummyApp()
    global_config = {"testing": True}

    filter = restrict.make_predicate_restriction(
        app,
        global_config,
        predicate=DummyPredicate,
        enabled=False,
        foo='Foo',
    )

    assert filter.app is app
    assert isinstance(filter.predicate, DummyPredicate)
    assert filter.predicate.foo == 'Foo'
    assert not filter.enabled


def test_make_predicate_restriction_w_enabled_string_predicate_w_args():
    app = DummyApp()
    global_config = {"testing": True}

    filter = restrict.make_predicate_restriction(
        app,
        global_config,
        predicate='test_restrict:DummyPredicate',
        enabled=True,
        foo='Foo'
    )

    assert filter.app is app
    assert isinstance(filter.predicate, DummyPredicate)
    assert filter.predicate.foo == 'Foo'
    assert filter.enabled


class DummyApp(object):
    environ = None
    def __call__(self, environ, start_response):
        self.environ = environ
        return []


class DummyPredicate(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)
