import io
import logging
import warnings

import pytest
from zope.interface import classImplements
from zope.interface import classImplementsOnly
from zope.interface import implementedBy

from repoze.who import config as config_module
from repoze.who import interfaces


@pytest.fixture
def dummy_plugin():
    before = implementedBy(DummyPlugin)
    yield DummyPlugin
    classImplementsOnly(DummyPlugin, before)


@pytest.fixture
def config_path(tmp_path):
    return tmp_path / "who.ini"


@pytest.fixture
def sample_config(config_path):
    config_path.write_text(SAMPLE_CONFIG)
    return config_path


def _getDummyPluginClass(iface):
    if not iface.implementedBy(DummyPlugin):
        classImplements(DummyPlugin, iface)
    return DummyPlugin


def test_whoconfig_defaults_before_parse():
    config = config_module.WhoConfig(here="/")

    assert config.request_classifier is None
    assert config.challenge_decider is None
    assert config.remote_user_key == 'REMOTE_USER'
    assert len(config.plugins) == 0
    assert len(config.identifiers) == 0
    assert len(config.authenticators) == 0
    assert len(config.challengers) == 0
    assert len(config.mdproviders) == 0


def test_whoconfig_parse_empty_string():
    config = config_module.WhoConfig(here="/")

    config.parse('')

    assert config.request_classifier is None
    assert config.challenge_decider is None
    assert config.remote_user_key == 'REMOTE_USER'
    assert len(config.plugins) == 0
    assert len(config.identifiers) == 0
    assert len(config.authenticators) == 0
    assert len(config.challengers) == 0
    assert len(config.mdproviders) == 0


def test_whoconfig_parse_empty_file():
    config = config_module.WhoConfig(here="/")

    config.parse(io.StringIO())

    assert config.request_classifier is None
    assert config.challenge_decider is None
    assert config.remote_user_key == 'REMOTE_USER'
    assert len(config.plugins) == 0
    assert len(config.identifiers) == 0
    assert len(config.authenticators) == 0
    assert len(config.challengers) == 0
    assert len(config.mdproviders) == 0


def test_whoconfig_parse_plugins():
    config = config_module.WhoConfig(here="/")

    config.parse(PLUGINS_ONLY)

    assert len(config.plugins) == 2
    assert isinstance(config.plugins['foo'], DummyPlugin)

    bar = config.plugins['bar']
    assert isinstance(bar, DummyPlugin)
    assert bar.credentials == 'qux'


def test_whoconfig_parse_general_empty():
    config = config_module.WhoConfig(here="/")

    config.parse('[general]')

    assert config.request_classifier is None
    assert config.challenge_decider is None
    assert config.remote_user_key == 'REMOTE_USER'
    assert len(config.plugins) == 0


def test_whoconfig_parse_general_only(dummy_plugin):
    class IDummy(
        interfaces.IRequestClassifier,
        interfaces.IChallengeDecider,
    ):
        pass

    PLUGIN_CLASS = _getDummyPluginClass(IDummy)
    config = config_module.WhoConfig(here="/")

    config.parse(GENERAL_ONLY)

    assert isinstance(config.request_classifier, PLUGIN_CLASS)
    assert isinstance(config.challenge_decider, PLUGIN_CLASS)
    assert config.remote_user_key == 'ANOTHER_REMOTE_USER'
    assert len(config.plugins) == 0


def test_whoconfig_parse_general_with_plugins(dummy_plugin):
    class IDummy(interfaces.IRequestClassifier, interfaces.IChallengeDecider):
        pass

    PLUGIN_CLASS = _getDummyPluginClass(IDummy)
    config = config_module.WhoConfig(here="/")

    config.parse(GENERAL_WITH_PLUGINS)

    assert isinstance(config.request_classifier, PLUGIN_CLASS)
    assert isinstance(config.challenge_decider, PLUGIN_CLASS)


def test_whoconfig_parse_identifiers_only(dummy_plugin):
    PLUGIN_CLASS = _getDummyPluginClass(interfaces.IIdentifier)
    config = config_module.WhoConfig(here="/")

    config.parse(IDENTIFIERS_ONLY)

    identifiers = config.identifiers
    assert len(identifiers) == 2

    first, second = identifiers
    assert first[0] == 'test_config:DummyPlugin'
    assert isinstance(first[1], PLUGIN_CLASS)
    assert len(first[1].classifications) == 1
    assert first[1].classifications[interfaces.IIdentifier] == 'klass1'
    assert second[0] == 'test_config:DummyPlugin'
    assert isinstance(second[1], PLUGIN_CLASS)


def test_whoconfig_parse_identifiers_with_plugins(dummy_plugin):
    PLUGIN_CLASS = _getDummyPluginClass(interfaces.IIdentifier)
    config = config_module.WhoConfig(here="/")

    config.parse(IDENTIFIERS_WITH_PLUGINS)

    identifiers = config.identifiers
    assert len(identifiers) == 2

    first, second = identifiers
    assert first[0] == 'foo'
    assert isinstance(first[1], PLUGIN_CLASS)
    assert len(first[1].classifications) == 1
    assert first[1].classifications[interfaces.IIdentifier] == 'klass1'
    assert second[0] == 'bar'
    assert isinstance(second[1], PLUGIN_CLASS)


def test_whoconfig_parse_authenticators_only(dummy_plugin):
    PLUGIN_CLASS = _getDummyPluginClass(interfaces.IAuthenticator)
    config = config_module.WhoConfig(here="/")

    config.parse(AUTHENTICATORS_ONLY)

    authenticators = config.authenticators
    assert len(authenticators) == 2

    first, second = authenticators
    assert first[0] == 'test_config:DummyPlugin'
    assert isinstance(first[1], PLUGIN_CLASS)
    assert len(first[1].classifications) == 1
    assert first[1].classifications[interfaces.IAuthenticator] == 'klass1'
    assert second[0] == 'test_config:DummyPlugin'
    assert isinstance(second[1], PLUGIN_CLASS)

def test_whoconfig_parse_authenticators_with_plugins(dummy_plugin):
    PLUGIN_CLASS = _getDummyPluginClass(interfaces.IAuthenticator)
    config = config_module.WhoConfig(here="/")

    config.parse(AUTHENTICATORS_WITH_PLUGINS)

    authenticators = config.authenticators
    assert len(authenticators) == 2

    first, second = authenticators
    assert first[0] == 'foo'
    assert isinstance(first[1], PLUGIN_CLASS)
    assert len(first[1].classifications) == 1
    assert first[1].classifications[interfaces.IAuthenticator] == 'klass1'
    assert second[0] == 'bar'
    assert isinstance(second[1], PLUGIN_CLASS)


def test_whoconfig_parse_challengers_only(dummy_plugin):
    PLUGIN_CLASS = _getDummyPluginClass(interfaces.IChallenger)
    config = config_module.WhoConfig(here="/")

    config.parse(CHALLENGERS_ONLY)

    challengers = config.challengers
    assert len(challengers) == 2

    first, second = challengers
    assert first[0] == 'test_config:DummyPlugin'
    assert isinstance(first[1], PLUGIN_CLASS)
    assert len(first[1].classifications) == 1
    assert first[1].classifications[interfaces.IChallenger] == 'klass1'
    assert second[0] == 'test_config:DummyPlugin'
    assert isinstance(second[1], PLUGIN_CLASS)


def test_whoconfig_parse_challengers_with_plugins(dummy_plugin):
    PLUGIN_CLASS = _getDummyPluginClass(interfaces.IChallenger)
    config = config_module.WhoConfig(here="/")

    config.parse(CHALLENGERS_WITH_PLUGINS)

    challengers = config.challengers
    assert len(challengers) == 2

    first, second = challengers
    assert first[0] == 'foo'
    assert isinstance(first[1], PLUGIN_CLASS)
    assert len(first[1].classifications) == 1
    assert first[1].classifications[interfaces.IChallenger] == 'klass1'
    assert second[0] == 'bar'
    assert isinstance(second[1], PLUGIN_CLASS)


def test_whoconfig_parse_mdproviders_only(dummy_plugin):
    PLUGIN_CLASS = _getDummyPluginClass(interfaces.IMetadataProvider)
    config = config_module.WhoConfig(here="/")

    config.parse(MDPROVIDERS_ONLY)

    mdproviders = config.mdproviders
    assert len(mdproviders) == 2

    first, second = mdproviders
    assert first[0] == 'test_config:DummyPlugin'
    assert isinstance(first[1], PLUGIN_CLASS)
    assert len(first[1].classifications) == 1
    assert first[1].classifications[interfaces.IMetadataProvider] == 'klass1'
    assert second[0] == 'test_config:DummyPlugin'
    assert isinstance(second[1], PLUGIN_CLASS)


def test_whoconfig_parse_mdproviders_with_plugins(dummy_plugin):
    PLUGIN_CLASS = _getDummyPluginClass(interfaces.IMetadataProvider)
    config = config_module.WhoConfig(here="/")

    config.parse(MDPROVIDERS_WITH_PLUGINS)

    mdproviders = config.mdproviders
    assert len(mdproviders) == 2

    first, second = mdproviders
    assert first[0] == 'foo'
    assert isinstance(first[1], PLUGIN_CLASS)
    assert len(first[1].classifications) == 1
    assert first[1].classifications[interfaces.IMetadataProvider] == 'klass1'
    assert second[0] == 'bar'
    assert isinstance(second[1], PLUGIN_CLASS)


def test_whoconfig_parse_make_plugin_names(dummy_plugin):
    # see http://bugs.repoze.org/issue92
    config = config_module.WhoConfig(here="/")

    config.parse(MAKE_PLUGIN_ARG_NAMES)

    assert len(config.plugins) == 1

    foo = config.plugins['foo']
    assert isinstance(foo, DummyPlugin)
    assert foo.iface == 'iface'
    assert foo.name == 'name'
    assert foo.template == '%(template)s'
    assert foo.template_with_eq == 'template_with_eq = %(template_with_eq)s'


class DummyPlugin:
    def __init__(self, **kw):
        self.__dict__.update(kw)


PLUGINS_ONLY = """\
[plugin:foo]
use = test_config:DummyPlugin

[plugin:bar]
use = test_config:DummyPlugin
credentials = qux
"""

GENERAL_ONLY = """\
[general]
request_classifier = test_config:DummyPlugin
challenge_decider = test_config:DummyPlugin
remote_user_key = ANOTHER_REMOTE_USER
"""

GENERAL_WITH_PLUGINS = """\
[general]
request_classifier = classifier
challenge_decider = decider

[plugin:classifier]
use = test_config:DummyPlugin

[plugin:decider]
use = test_config:DummyPlugin
"""

IDENTIFIERS_ONLY = """\
[identifiers]
plugins =
    test_config:DummyPlugin;klass1
    test_config:DummyPlugin
"""

IDENTIFIERS_WITH_PLUGINS = """\
[identifiers]
plugins =
    foo;klass1
    bar

[plugin:foo]
use = test_config:DummyPlugin

[plugin:bar]
use = test_config:DummyPlugin
"""

AUTHENTICATORS_ONLY = """\
[authenticators]
plugins =
    test_config:DummyPlugin;klass1
    test_config:DummyPlugin
"""

AUTHENTICATORS_WITH_PLUGINS = """\
[authenticators]
plugins =
    foo;klass1
    bar

[plugin:foo]
use = test_config:DummyPlugin

[plugin:bar]
use = test_config:DummyPlugin
"""

CHALLENGERS_ONLY = """\
[challengers]
plugins =
    test_config:DummyPlugin;klass1
    test_config:DummyPlugin
"""

CHALLENGERS_WITH_PLUGINS = """\
[challengers]
plugins =
    foo;klass1
    bar

[plugin:foo]
use = test_config:DummyPlugin

[plugin:bar]
use = test_config:DummyPlugin
"""

MDPROVIDERS_ONLY = """\
[mdproviders]
plugins =
    test_config:DummyPlugin;klass1
    test_config:DummyPlugin
"""

MDPROVIDERS_WITH_PLUGINS = """\
[mdproviders]
plugins =
    foo;klass1
    bar

[plugin:foo]
use = test_config:DummyPlugin

[plugin:bar]
use = test_config:DummyPlugin
"""

MAKE_PLUGIN_ARG_NAMES = """\
[plugin:foo]
use = test_config:DummyPlugin
name = name
iface = iface
template = %%(template)s
template_with_eq = template_with_eq = %%(template_with_eq)s
"""


def test_config_mw_w_sample_config(sample_config):
    app = DummyApp()
    global_conf = {'here': '/'}
    middleware = config_module.make_middleware_with_config(
        app,
        global_conf,
        config_file=str(sample_config),
        log_file='STDOUT',
        log_level='debug',
    )

    api_factory = middleware.api_factory

    assert len(api_factory.identifiers) == 2
    assert len(api_factory.authenticators) == 1
    assert len(api_factory.challengers) == 2
    assert len(api_factory.mdproviders) == 0

    assert middleware.logger
    assert middleware.logger.getEffectiveLevel() == logging.DEBUG


def test_config_mw_w_sample_config_no_log_level(sample_config):
    app = DummyApp()
    global_conf = {'here': '/'}
    middleware = config_module.make_middleware_with_config(
        app,
        global_conf,
        config_file=str(sample_config),
        log_file='STDOUT',
    )

    assert middleware.logger.getEffectiveLevel() == logging.INFO


def test_config_mw_w_sample_config_w_log_file(tmp_path, sample_config):
    app = DummyApp()
    logfile = tmp_path / 'who.log'
    global_conf = {'here': '/'}

    middleware = config_module.make_middleware_with_config(
        app,
        global_conf,
        config_file=str(sample_config),
        log_file=str(logfile),
        log_level=logging.WARN
    )

    assert middleware.logger.getEffectiveLevel() == logging.WARN

    handlers = middleware.logger.handlers
    assert len(handlers) == 1
    assert isinstance(handlers[0], logging.StreamHandler)
    assert handlers[0].stream.name == str(logfile)

    logging.shutdown()
    handlers[0].stream.close()


def test_config_mw_w_sample_config_wo_log_file(sample_config):
    app = DummyApp()
    global_conf = {'here': '/'}
    middleware = config_module.make_middleware_with_config(
        app,
        global_conf,
        config_file=str(sample_config),
    )

    assert middleware.logger.getEffectiveLevel() == logging.INFO

    handlers = middleware.logger.handlers
    assert len(handlers) == 1
    assert isinstance(handlers[0], config_module.NullHandler)

    logging.shutdown()


def test_nullhandler_inheritance():
    handler = config_module.NullHandler()
    assert isinstance(handler, logging.Handler)


def test_nullhandler_emit_doesnt_raise_NotImplementedError():
    handler = config_module.NullHandler()
    handler.emit(object())


def test_bad_config_filename(tmp_path):
    bad_file = tmp_path / "nonesuch" / "who.ini"
    global_conf = {'here': '/'}

    with warnings.catch_warnings(record=True) as warned:
        api_factory = config_module.make_api_factory_with_config(
            global_conf,
            config_file=str(bad_file),
        )

    assert len(api_factory.identifiers) == 0
    assert len(api_factory.authenticators) == 0
    assert len(api_factory.challengers) == 0
    assert len(api_factory.mdproviders) == 0
    assert api_factory.remote_user_key == 'REMOTE_USER'
    assert api_factory.logger is None

    assert warned


def test_bad_config_content(config_path):
    config_path.write_text('this is not an INI file')
    global_conf = {'here': '/'}

    with warnings.catch_warnings(record=True) as warned:
        api_factory = config_module.make_api_factory_with_config(
            global_conf,
            config_file=str(config_path),
        )

    assert len(api_factory.identifiers) == 0
    assert len(api_factory.authenticators) == 0
    assert len(api_factory.challengers) == 0
    assert len(api_factory.mdproviders) == 0
    assert api_factory.remote_user_key == 'REMOTE_USER'
    assert api_factory.logger is None

    assert warned


def test_sample_config_no_logger(sample_config):
    global_conf = {'here': '/'}

    api_factory = config_module.make_api_factory_with_config(
        global_conf,
        config_file=str(sample_config),
    )

    assert len(api_factory.identifiers) == 2
    assert len(api_factory.authenticators) == 1
    assert len(api_factory.challengers) == 2
    assert len(api_factory.mdproviders) == 0
    assert api_factory.remote_user_key == 'REMOTE_USER'
    assert api_factory.logger is None

def test_sample_config_w_remote_user_key(sample_config):
    global_conf = {'here': '/'}

    api_factory = config_module.make_api_factory_with_config(
        global_conf,
        config_file=str(sample_config),
        remote_user_key = 'X-OTHER-USER',
    )

    assert len(api_factory.identifiers) == 2
    assert len(api_factory.authenticators) == 1
    assert len(api_factory.challengers) == 2
    assert len(api_factory.mdproviders) == 0
    assert api_factory.remote_user_key == 'X-OTHER-USER'

def test_sample_config_w_logger(sample_config):
    global_conf = {'here': '/'}
    logger = object()

    api_factory = config_module.make_api_factory_with_config(
        global_conf,
        config_file=str(sample_config),
        logger=logger,
    )

    assert len(api_factory.identifiers) == 2
    assert len(api_factory.authenticators) == 1
    assert len(api_factory.challengers) == 2
    assert len(api_factory.mdproviders) == 0
    assert api_factory.logger is logger


SAMPLE_CONFIG = """\
[plugin:redirector]
use = repoze.who.plugins.redirector:make_plugin
login_url = /login.html

[plugin:auth_tkt]
use = repoze.who.plugins.auth_tkt:make_plugin
secret = s33kr1t
cookie_name = oatmeal
secure = False
include_ip = True

[plugin:basicauth]
use = repoze.who.plugins.basicauth:make_plugin
realm = 'sample'

[plugin:htpasswd]
use = repoze.who.plugins.htpasswd:make_plugin
filename = %(here)s/etc/passwd
check_fn = repoze.who.plugins.htpasswd:crypt_check

[general]
request_classifier = repoze.who.classifiers:default_request_classifier
challenge_decider = repoze.who.classifiers:default_challenge_decider

[identifiers]
plugins =
    auth_tkt
    basicauth

[authenticators]
plugins = htpasswd

[challengers]
plugins =
    redirector;browser
    basicauth

[mdproviders]
plugins =

"""

class DummyApp:
    environ = None
