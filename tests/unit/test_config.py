import io
import logging
import unittest

from zope.interface import classImplements

from repoze.who import config
from repoze.who import interfaces


class TestWhoConfig(unittest.TestCase):

    def _getTargetClass(self):
        return config.WhoConfig

    def _makeOne(self, here='/', *args, **kw):
        return self._getTargetClass()(here, *args, **kw)

    def _getDummyPluginClass(self, iface):
        if not iface.implementedBy(DummyPlugin):
            classImplements(DummyPlugin, iface)
        return DummyPlugin

    def test_defaults_before_parse(self):
        config = self._makeOne()
        self.assertEqual(config.request_classifier, None)
        self.assertEqual(config.challenge_decider, None)
        self.assertEqual(config.remote_user_key, 'REMOTE_USER')
        self.assertEqual(len(config.plugins), 0)
        self.assertEqual(len(config.identifiers), 0)
        self.assertEqual(len(config.authenticators), 0)
        self.assertEqual(len(config.challengers), 0)
        self.assertEqual(len(config.mdproviders), 0)

    def test_parse_empty_string(self):
        config = self._makeOne()
        config.parse('')
        self.assertEqual(config.request_classifier, None)
        self.assertEqual(config.challenge_decider, None)
        self.assertEqual(config.remote_user_key, 'REMOTE_USER')
        self.assertEqual(len(config.plugins), 0)
        self.assertEqual(len(config.identifiers), 0)
        self.assertEqual(len(config.authenticators), 0)
        self.assertEqual(len(config.challengers), 0)
        self.assertEqual(len(config.mdproviders), 0)

    def test_parse_empty_file(self):
        config = self._makeOne()
        config.parse(io.StringIO())
        self.assertEqual(config.request_classifier, None)
        self.assertEqual(config.challenge_decider, None)
        self.assertEqual(config.remote_user_key, 'REMOTE_USER')
        self.assertEqual(len(config.plugins), 0)
        self.assertEqual(len(config.identifiers), 0)
        self.assertEqual(len(config.authenticators), 0)
        self.assertEqual(len(config.challengers), 0)
        self.assertEqual(len(config.mdproviders), 0)

    def test_parse_plugins(self):
        config = self._makeOne()
        config.parse(PLUGINS_ONLY)
        self.assertEqual(len(config.plugins), 2)
        self.assertTrue(isinstance(config.plugins['foo'],
                                   DummyPlugin))
        bar = config.plugins['bar']
        self.assertTrue(isinstance(bar, DummyPlugin))
        self.assertEqual(bar.credentials, 'qux')

    def test_parse_general_empty(self):
        config = self._makeOne()
        config.parse('[general]')
        self.assertEqual(config.request_classifier, None)
        self.assertEqual(config.challenge_decider, None)
        self.assertEqual(config.remote_user_key, 'REMOTE_USER')
        self.assertEqual(len(config.plugins), 0)

    def test_parse_general_only(self):
        class IDummy(interfaces.IRequestClassifier, interfaces.IChallengeDecider):
            pass
        PLUGIN_CLASS = self._getDummyPluginClass(IDummy)
        config = self._makeOne()
        config.parse(GENERAL_ONLY)
        self.assertTrue(isinstance(config.request_classifier, PLUGIN_CLASS))
        self.assertTrue(isinstance(config.challenge_decider, PLUGIN_CLASS))
        self.assertEqual(config.remote_user_key, 'ANOTHER_REMOTE_USER')
        self.assertEqual(len(config.plugins), 0)

    def test_parse_general_with_plugins(self):
        class IDummy(interfaces.IRequestClassifier, interfaces.IChallengeDecider):
            pass
        PLUGIN_CLASS = self._getDummyPluginClass(IDummy)
        config = self._makeOne()
        config.parse(GENERAL_WITH_PLUGINS)
        self.assertTrue(isinstance(config.request_classifier, PLUGIN_CLASS))
        self.assertTrue(isinstance(config.challenge_decider, PLUGIN_CLASS))

    def test_parse_identifiers_only(self):
        PLUGIN_CLASS = self._getDummyPluginClass(interfaces.IIdentifier)
        config = self._makeOne()
        config.parse(IDENTIFIERS_ONLY)
        identifiers = config.identifiers
        self.assertEqual(len(identifiers), 2)
        first, second = identifiers
        self.assertEqual(first[0], 'test_config:DummyPlugin')
        self.assertTrue(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[interfaces.IIdentifier], 'klass1')
        self.assertEqual(second[0], 'test_config:DummyPlugin')
        self.assertTrue(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_identifiers_with_plugins(self):
        PLUGIN_CLASS = self._getDummyPluginClass(interfaces.IIdentifier)
        config = self._makeOne()
        config.parse(IDENTIFIERS_WITH_PLUGINS)
        identifiers = config.identifiers
        self.assertEqual(len(identifiers), 2)
        first, second = identifiers
        self.assertEqual(first[0], 'foo')
        self.assertTrue(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[interfaces.IIdentifier], 'klass1')
        self.assertEqual(second[0], 'bar')
        self.assertTrue(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_authenticators_only(self):
        PLUGIN_CLASS = self._getDummyPluginClass(interfaces.IAuthenticator)
        config = self._makeOne()
        config.parse(AUTHENTICATORS_ONLY)
        authenticators = config.authenticators
        self.assertEqual(len(authenticators), 2)
        first, second = authenticators
        self.assertEqual(first[0], 'test_config:DummyPlugin')
        self.assertTrue(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[interfaces.IAuthenticator], 'klass1')
        self.assertEqual(second[0], 'test_config:DummyPlugin')
        self.assertTrue(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_authenticators_with_plugins(self):
        PLUGIN_CLASS = self._getDummyPluginClass(interfaces.IAuthenticator)
        config = self._makeOne()
        config.parse(AUTHENTICATORS_WITH_PLUGINS)
        authenticators = config.authenticators
        self.assertEqual(len(authenticators), 2)
        first, second = authenticators
        self.assertEqual(first[0], 'foo')
        self.assertTrue(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[interfaces.IAuthenticator], 'klass1')
        self.assertEqual(second[0], 'bar')
        self.assertTrue(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_challengers_only(self):
        PLUGIN_CLASS = self._getDummyPluginClass(interfaces.IChallenger)
        config = self._makeOne()
        config.parse(CHALLENGERS_ONLY)
        challengers = config.challengers
        self.assertEqual(len(challengers), 2)
        first, second = challengers
        self.assertEqual(first[0], 'test_config:DummyPlugin')
        self.assertTrue(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[interfaces.IChallenger], 'klass1')
        self.assertEqual(second[0], 'test_config:DummyPlugin')
        self.assertTrue(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_challengers_with_plugins(self):
        PLUGIN_CLASS = self._getDummyPluginClass(interfaces.IChallenger)
        config = self._makeOne()
        config.parse(CHALLENGERS_WITH_PLUGINS)
        challengers = config.challengers
        self.assertEqual(len(challengers), 2)
        first, second = challengers
        self.assertEqual(first[0], 'foo')
        self.assertTrue(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[interfaces.IChallenger], 'klass1')
        self.assertEqual(second[0], 'bar')
        self.assertTrue(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_mdproviders_only(self):
        PLUGIN_CLASS = self._getDummyPluginClass(interfaces.IMetadataProvider)
        config = self._makeOne()
        config.parse(MDPROVIDERS_ONLY)
        mdproviders = config.mdproviders
        self.assertEqual(len(mdproviders), 2)
        first, second = mdproviders
        self.assertEqual(first[0], 'test_config:DummyPlugin')
        self.assertTrue(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[interfaces.IMetadataProvider], 'klass1')
        self.assertEqual(second[0], 'test_config:DummyPlugin')
        self.assertTrue(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_mdproviders_with_plugins(self):
        PLUGIN_CLASS = self._getDummyPluginClass(interfaces.IMetadataProvider)
        config = self._makeOne()
        config.parse(MDPROVIDERS_WITH_PLUGINS)
        mdproviders = config.mdproviders
        self.assertEqual(len(mdproviders), 2)
        first, second = mdproviders
        self.assertEqual(first[0], 'foo')
        self.assertTrue(isinstance(first[1], PLUGIN_CLASS))
        self.assertEqual(len(first[1].classifications), 1)
        self.assertEqual(first[1].classifications[interfaces.IMetadataProvider], 'klass1')
        self.assertEqual(second[0], 'bar')
        self.assertTrue(isinstance(second[1], PLUGIN_CLASS))

    def test_parse_make_plugin_names(self):
        # see http://bugs.repoze.org/issue92
        config = self._makeOne()
        config.parse(MAKE_PLUGIN_ARG_NAMES)
        self.assertEqual(len(config.plugins), 1)
        foo = config.plugins['foo']
        self.assertTrue(isinstance(foo, DummyPlugin))
        self.assertEqual(foo.iface, 'iface')
        self.assertEqual(foo.name, 'name')
        self.assertEqual(foo.template, '%(template)s')
        self.assertEqual(foo.template_with_eq,
                         'template_with_eq = %(template_with_eq)s')

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

class TestConfigMiddleware(unittest.TestCase):
    _tempdir = None

    def setUp(self):
        pass

    def tearDown(self):
        if self._tempdir is not None:
            import shutil
            shutil.rmtree(self._tempdir)

    def _getFactory(self):
        return config.make_middleware_with_config

    def _getTempfile(self, text):
        import os
        import tempfile
        tempdir = self._tempdir = tempfile.mkdtemp()
        path = os.path.join(tempdir, 'who.ini')
        config = open(path, 'w')
        config.write(text)
        config.flush()
        config.close()
        return path

    def test_sample_config(self):
        import logging
        app = DummyApp()
        factory = self._getFactory()
        path = self._getTempfile(SAMPLE_CONFIG)
        global_conf = {'here': '/'}
        middleware = factory(app, global_conf, config_file=path,
                             log_file='STDOUT', log_level='debug')
        api_factory = middleware.api_factory
        self.assertEqual(len(api_factory.identifiers), 2)
        self.assertEqual(len(api_factory.authenticators), 1)
        self.assertEqual(len(api_factory.challengers), 2)
        self.assertEqual(len(api_factory.mdproviders), 0)
        self.assertTrue(middleware.logger, middleware.logger)
        self.assertEqual(middleware.logger.getEffectiveLevel(), logging.DEBUG)

    def test_sample_config_no_log_level(self):
        import logging
        app = DummyApp()
        factory = self._getFactory()
        path = self._getTempfile(SAMPLE_CONFIG)
        global_conf = {'here': '/'}
        middleware = factory(app, global_conf, config_file=path,
                             log_file='STDOUT')
        self.assertEqual(middleware.logger.getEffectiveLevel(), logging.INFO)

    def test_sample_config_w_log_file(self):
        import logging
        import os
        app = DummyApp()
        factory = self._getFactory()
        path = self._getTempfile(SAMPLE_CONFIG)
        logfile = os.path.join(self._tempdir, 'who.log')
        global_conf = {'here': '/'}
        middleware = factory(app, global_conf, config_file=path,
                             log_file=logfile, log_level=logging.WARN)
        self.assertEqual(middleware.logger.getEffectiveLevel(), logging.WARN)
        handlers = middleware.logger.handlers
        self.assertEqual(len(handlers), 1)
        self.assertTrue(isinstance(handlers[0], logging.StreamHandler))
        self.assertEqual(handlers[0].stream.name, logfile)
        logging.shutdown()
        handlers[0].stream.close()

    def test_sample_config_wo_log_file(self):
        app = DummyApp()
        factory = self._getFactory()
        path = self._getTempfile(SAMPLE_CONFIG)
        global_conf = {'here': '/'}
        middleware = factory(app, global_conf, config_file=path)
        self.assertEqual(middleware.logger.getEffectiveLevel(), logging.INFO)
        handlers = middleware.logger.handlers
        self.assertEqual(len(handlers), 1)
        self.assertTrue(isinstance(handlers[0], config.NullHandler))
        logging.shutdown()

class NullHandlerTests(unittest.TestCase):

    def _getTargetClass(self):
        return config.NullHandler

    def _makeOne(self):
        return self._getTargetClass()()

    def test_inheritance(self):
        import logging
        handler = self._makeOne()
        self.assertTrue(isinstance(handler, logging.Handler))

    def test_emit_doesnt_raise_NotImplementedError(self):
        handler = self._makeOne()
        handler.emit(object())

class Test_make_api_factory_with_config(unittest.TestCase):
    _tempdir = None

    def setUp(self):
        pass

    def tearDown(self):
        if self._tempdir is not None:
            import shutil
            shutil.rmtree(self._tempdir)

    def _getFactory(self):
        return config.make_api_factory_with_config

    def _getTempfile(self, text):
        import os
        import tempfile
        tempdir = self._tempdir = tempfile.mkdtemp()
        path = os.path.join(tempdir, 'who.ini')
        config = open(path, 'w')
        config.write(text)
        config.flush()
        config.close()
        return path

    def test_bad_config_filename(self):
        import warnings
        with warnings.catch_warnings(record=True) as warned:
            factory = self._getFactory()
            path = '/nonesuch/file/should/exist'
            global_conf = {'here': '/'}
            api_factory = factory(global_conf, config_file=path)
            self.assertEqual(len(api_factory.identifiers), 0)
            self.assertEqual(len(api_factory.authenticators), 0)
            self.assertEqual(len(api_factory.challengers), 0)
            self.assertEqual(len(api_factory.mdproviders), 0)
            self.assertEqual(api_factory.remote_user_key, 'REMOTE_USER')
            self.assertTrue(api_factory.logger is None)
            self.assertTrue(warned)

    def test_bad_config_content(self):
        import warnings
        with warnings.catch_warnings(record=True) as warned:
            factory = self._getFactory()
            path = self._getTempfile('this is not an INI file')
            global_conf = {'here': '/'}
            api_factory = factory(global_conf, config_file=path)
            self.assertEqual(len(api_factory.identifiers), 0)
            self.assertEqual(len(api_factory.authenticators), 0)
            self.assertEqual(len(api_factory.challengers), 0)
            self.assertEqual(len(api_factory.mdproviders), 0)
            self.assertEqual(api_factory.remote_user_key, 'REMOTE_USER')
            self.assertTrue(api_factory.logger is None)
            self.assertTrue(warned)

    def test_sample_config_no_logger(self):
        factory = self._getFactory()
        path = self._getTempfile(SAMPLE_CONFIG)
        global_conf = {'here': '/'}
        api_factory = factory(global_conf, config_file=path)
        self.assertEqual(len(api_factory.identifiers), 2)
        self.assertEqual(len(api_factory.authenticators), 1)
        self.assertEqual(len(api_factory.challengers), 2)
        self.assertEqual(len(api_factory.mdproviders), 0)
        self.assertEqual(api_factory.remote_user_key, 'REMOTE_USER')
        self.assertTrue(api_factory.logger is None)

    def test_sample_config_w_remote_user_key(self):
        factory = self._getFactory()
        path = self._getTempfile(SAMPLE_CONFIG)
        global_conf = {'here': '/'}
        api_factory = factory(global_conf, config_file=path,
                              remote_user_key = 'X-OTHER-USER')
        self.assertEqual(len(api_factory.identifiers), 2)
        self.assertEqual(len(api_factory.authenticators), 1)
        self.assertEqual(len(api_factory.challengers), 2)
        self.assertEqual(len(api_factory.mdproviders), 0)
        self.assertEqual(api_factory.remote_user_key, 'X-OTHER-USER')

    def test_sample_config_w_logger(self):
        factory = self._getFactory()
        path = self._getTempfile(SAMPLE_CONFIG)
        global_conf = {'here': '/'}
        logger = object()
        api_factory = factory(global_conf, config_file=path, logger=logger)
        self.assertEqual(len(api_factory.identifiers), 2)
        self.assertEqual(len(api_factory.authenticators), 1)
        self.assertEqual(len(api_factory.challengers), 2)
        self.assertEqual(len(api_factory.mdproviders), 0)
        self.assertTrue(api_factory.logger is logger)

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
