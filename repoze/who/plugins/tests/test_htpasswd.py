try:
    from crypt import crypt
except ImportError:
    # The crypt module is deprecated since Python 3.11
    # and will be removed in Python 3.13.
    # win32 does not have a crypt library at all.
    crypt = None
import unittest
import warnings

import pytest


class TestHTPasswdPlugin(unittest.TestCase):

    def _getTargetClass(self):
        from repoze.who.plugins.htpasswd import HTPasswdPlugin
        return HTPasswdPlugin

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def _makeEnviron(self):
        environ = {}
        environ['wsgi.version'] = (1,0)
        return environ

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IAuthenticator
        klass = self._getTargetClass()
        verifyClass(IAuthenticator, klass)

    def test_authenticate_nocreds(self):
        from io import StringIO
        io = StringIO()
        plugin = self._makeOne(io, None)
        environ = self._makeEnviron()
        creds = {}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, None)

    def test_authenticate_nolines(self):
        from io import StringIO
        io = StringIO()
        def check(password, hashed):
            return True
        plugin = self._makeOne(io, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, None)

    def test_authenticate_nousermatch(self):
        from io import StringIO
        io = StringIO('nobody:foo')
        def check(password, hashed):
            return True
        plugin = self._makeOne(io, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, None)

    def test_authenticate_match(self):
        from io import StringIO
        io = StringIO('chrism:pass')
        def check(password, hashed):
            return True
        plugin = self._makeOne(io, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, 'chrism')

    def test_authenticate_badline(self):
        from io import StringIO
        io = StringIO('badline\nchrism:pass')
        def check(password, hashed):
            return True
        plugin = self._makeOne(io, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, 'chrism')

    def test_authenticate_filename(self):
        import os
        here = os.path.abspath(os.path.dirname(__file__))
        htpasswd = os.path.join(here, 'fixtures', 'test.htpasswd')
        def check(password, hashed):
            return True
        plugin = self._makeOne(htpasswd, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, 'chrism')

    def test_authenticate_bad_filename_logs_to_repoze_who_logger(self):
        import os
        here = os.path.abspath(os.path.dirname(__file__))
        htpasswd = os.path.join(here, 'fixtures', 'test.htpasswd.nonesuch')
        def check(password, hashed): # pragma: no cover
            return True
        plugin = self._makeOne(htpasswd, check)
        environ = self._makeEnviron()
        class DummyLogger:
            warnings = []
            def warn(self, msg):
                self.warnings.append(msg)
        logger = environ['repoze.who.logger'] = DummyLogger()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, None)
        self.assertEqual(len(logger.warnings), 1)
        self.assertTrue('could not open htpasswd' in logger.warnings[0])

    @unittest.skipIf(crypt is None, "crypt module not available")
    def test_crypt_check_hit(self):
        from repoze.who.plugins.htpasswd import crypt_check
        salt = '123'
        hashed = crypt('password', salt)

        with warnings.catch_warnings(record=True) as logged:
            assert crypt_check('password', hashed)

        assert len(logged) == 1
        record = logged[0]
        assert record.category is UserWarning
        assert "'crypt' module is deprecated" in str(record.message)

    @unittest.skipIf(crypt is None, "crypt module not available")
    def test_crypt_check_miss(self):
        from repoze.who.plugins.htpasswd import crypt_check
        salt = '123'
        hashed = crypt('password', salt)

        with warnings.catch_warnings(record=True) as logged:
            assert not crypt_check('notpassword', hashed)

        assert len(logged) == 1
        record = logged[0]
        assert record.category is UserWarning
        assert "'crypt' module is deprecated" in str(record.message)

    @unittest.skipIf(crypt is not None, "crypt module available")
    def test_crypt_check_gone(self):
        from repoze.who.plugins.htpasswd import CryptModuleNotImportable
        from repoze.who.plugins.htpasswd import crypt_check

        with pytest.raises(CryptModuleNotImportable):
            crypt_check('password', 'hashed')

    def test_sha1_check_w_password_str(self):
        from base64 import standard_b64encode
        from hashlib import sha1
        from repoze.who.plugins.htpasswd import sha1_check

        password = u'password'
        b_password = password.encode("ascii")
        encrypted_string = standard_b64encode(sha1(b_password).digest())
        hashed = b"%s%s" % (b"{SHA}", encrypted_string)

        self.assertTrue(sha1_check(password, hashed))
        self.assertFalse(sha1_check('notpassword', hashed))

    def test_sha1_check_w_password_bytes(self):
        from base64 import standard_b64encode
        from hashlib import sha1
        from repoze.who.plugins.htpasswd import sha1_check

        b_password = b'password'
        encrypted_string = standard_b64encode(sha1(b_password).digest())
        hashed = b"%s%s" % (b"{SHA}", encrypted_string)

        self.assertTrue(sha1_check(b_password, hashed))
        self.assertFalse(sha1_check(b'notpassword', hashed))

    def test_plain_check(self):
        from repoze.who.plugins.htpasswd import plain_check
        self.assertTrue(plain_check('password', 'password'))
        self.assertFalse(plain_check('notpassword', 'password'))

    def test_factory_no_filename_raises(self):
        from repoze.who.plugins.htpasswd import make_plugin
        self.assertRaises(ValueError, make_plugin)

    def test_factory_no_check_fn_raises(self):
        from repoze.who.plugins.htpasswd import make_plugin
        self.assertRaises(ValueError, make_plugin, 'foo')

    def test_factory(self):
        from repoze.who.plugins.htpasswd import make_plugin
        from repoze.who.plugins.htpasswd import crypt_check
        plugin = make_plugin('foo',
                             'repoze.who.plugins.htpasswd:crypt_check')
        self.assertEqual(plugin.filename, 'foo')
        self.assertEqual(plugin.check, crypt_check)
