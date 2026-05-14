from wsgiref.util import setup_testing_defaults

from repoze.who import classifiers
from repoze.who import interfaces


def _make_wsgi_environ():
    environ = {}
    setup_testing_defaults(environ)
    return environ


def test_drc_conforms_to_IRequestClassifier():
    assert interfaces.IRequestClassifier.providedBy(
        classifiers.default_request_classifier
    )


def test_drc_classify_dav_method():
    environ = _make_wsgi_environ() | {'REQUEST_METHOD':'COPY'}

    result = classifiers.default_request_classifier(environ)

    assert result == 'dav'


def test_drc_classify_dav_useragent():
    environ = _make_wsgi_environ() | {'HTTP_USER_AGENT':'WebDrive'}

    result = classifiers.default_request_classifier(environ)

    assert result == 'dav'


def test_drc_classify_xmlpost():
    environ = _make_wsgi_environ() | {
        'CONTENT_TYPE':'text/xml',
        'REQUEST_METHOD':'POST',
    }

    result = classifiers.default_request_classifier(environ)

    assert result == 'xmlpost'


def test_drc_classify_xmlpost_uppercase():
    # RFC 2045, Sec. 5.1:
    # The type, subtype, and parameter names are not case sensitive
    environ = _make_wsgi_environ() | {
        'CONTENT_TYPE':'TEXT/XML',
        'REQUEST_METHOD':'POST',
    }

    result = classifiers.default_request_classifier(environ)

    assert result == 'xmlpost'


def test_drc_classify_rich_xmlpost():
    # RFC 2046, sec. 4.1.2:
    # A critical parameter that may be specified in the Content-Type
    # field for "text/plain" data is the character set.
    environ = _make_wsgi_environ() | {
        'CONTENT_TYPE':'text/xml; charset=UTF-8 (some comment)',
        'REQUEST_METHOD':'POST',
    }

    result = classifiers.default_request_classifier(environ)

    assert result == 'xmlpost'


def test_drc_classify_browser():
    environ = _make_wsgi_environ() | {
        'CONTENT_TYPE':'text/xml',
        'REQUEST_METHOD':'GET',
    }

    result = classifiers.default_request_classifier(environ)

    assert result == 'browser'


def test_dcd_conforms_to_IChallengeDecider():
    assert interfaces.IChallengeDecider.providedBy(
        classifiers.default_challenge_decider
    )


def test_dcd_challenges_on_401():
    result = classifiers.default_challenge_decider(
        {}, '401 Unauthorized', [],
    )

    assert result


def test_dcd_doesnt_challenge_on_non_401():
    result = classifiers.default_challenge_decider({}, '200 Ok', [])

    assert not result


def test_pcd_conforms_to_IChallengeDecider():
    assert interfaces.IChallengeDecider.providedBy(
        classifiers.passthrough_challenge_decider
)


def test_pcd_challenges_on_bare_401():
    result = classifiers.passthrough_challenge_decider(
        {}, '401 Unauthorized', [],
    )
    assert result


def test_pcd_doesnt_challenge_on_non_401():
    result = classifiers.passthrough_challenge_decider({}, '200 Ok', [])

    assert not result


def test_pcd_doesnt_challenge_on_401_with_WWW_Authenticate():
    result = classifiers.passthrough_challenge_decider(
        {}, '401 Ok', [('WWW-Authenticate', 'xxx')],
    )

    assert not result


def test_pcd_doesnt_challenge_on_401_with_text_html():
    result = classifiers.passthrough_challenge_decider(
        {}, '401 Ok', [('Content-Type', 'text/html')],
    )

    assert not result
