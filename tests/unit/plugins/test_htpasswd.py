import base64
import hashlib
import io
import os
import unittest
import warnings

import pytest
from zope.interface import verify # verifyClass

from repoze.who import interfaces
from repoze.who.plugins import htpasswd


class TestHTPasswdPlugin(unittest.TestCase):

    def _getTargetClass(self):
        return htpasswd.HTPasswdPlugin

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def _makeEnviron(self):
        environ = {}
        environ['wsgi.version'] = (1,0)
        return environ

    def test_implements(self):
        verify.verifyClass(interfaces.IAuthenticator, htpasswd.HTPasswdPlugin)

    def test_authenticate_nocreds(self):
        buf = io.StringIO()
        plugin = self._makeOne(buf, None)
        environ = self._makeEnviron()
        creds = {}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, None)

    def test_authenticate_nolines(self):
        buf = io.StringIO()
        def check(password, hashed):
            return True
        plugin = self._makeOne(buf, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, None)

    def test_authenticate_nousermatch(self):
        buf = io.StringIO('nobody:foo')
        def check(password, hashed):
            return True
        plugin = self._makeOne(buf, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, None)

    def test_authenticate_match(self):
        buf = io.StringIO('chrism:pass')
        def check(password, hashed):
            return True
        plugin = self._makeOne(buf, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, 'chrism')

    def test_authenticate_badline(self):
        buf = io.StringIO('badline\nchrism:pass')
        def check(password, hashed):
            return True
        plugin = self._makeOne(buf, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, 'chrism')

    def test_authenticate_filename(self):
        here = os.path.abspath(os.path.dirname(__file__))
        htpasswd_file = os.path.join(here, 'fixtures', 'test.htpasswd')
        def check(password, hashed):
            return True
        plugin = self._makeOne(htpasswd_file, check)
        environ = self._makeEnviron()
        creds = {'login':'chrism', 'password':'pass'}
        result = plugin.authenticate(environ, creds)
        self.assertEqual(result, 'chrism')

    def test_authenticate_bad_filename_logs_to_repoze_who_logger(self):
        here = os.path.abspath(os.path.dirname(__file__))
        htpasswd_file = os.path.join(here, 'fixtures', 'test.htpasswd.nonesuch')
        def check(password, hashed): # pragma: no cover
            return True
        plugin = self._makeOne(htpasswd_file, check)
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

    @unittest.skipUnless(htpasswd.HAS_CRYPT, "crypt module not available")
    def test_crypt_check_hit(self):
        import crypt

        salt = '123'
        hashed = crypt.crypt('password', salt)

        with warnings.catch_warnings(record=True) as logged:
            assert htpasswd.crypt_check('password', hashed)

        assert len(logged) == 1
        record = logged[0]
        assert record.category is UserWarning
        assert "'crypt' module is deprecated" in str(record.message)

    @unittest.skipUnless(htpasswd.HAS_CRYPT, "crypt module not available")
    def test_crypt_check_miss(self):
        import crypt

        salt = '123'
        hashed = crypt.crypt('password', salt)

        with warnings.catch_warnings(record=True) as logged:
            assert not htpasswd.crypt_check('notpassword', hashed)

        assert len(logged) == 1
        record = logged[0]
        assert record.category is UserWarning
        assert "'crypt' module is deprecated" in str(record.message)

    @unittest.skipIf(htpasswd.HAS_CRYPT, "crypt module available")
    def test_crypt_check_gone(self):
        from repoze.who.plugins.htpasswd import CryptModuleNotImportable

        with pytest.raises(CryptModuleNotImportable):
            htpasswd.crypt_check('password', 'hashed')

    def test_sha1_check_w_password_str(self):
        password = u'password'
        b_password = password.encode("ascii")
        encrypted_string = base64.standard_b64encode(
            hashlib.sha1(
                b_password
            ).digest()
        )
        hashed = b"%s%s" % (b"{SHA}", encrypted_string)

        self.assertTrue(htpasswd.sha1_check(password, hashed))
        self.assertFalse(htpasswd.sha1_check('notpassword', hashed))

    def test_sha1_check_w_password_bytes(self):

        b_password = b'password'
        encrypted_string = base64.standard_b64encode(
            hashlib.sha1(
                b_password
            ).digest()
        )
        hashed = b"%s%s" % (b"{SHA}", encrypted_string)

        self.assertTrue(htpasswd.sha1_check(b_password, hashed))
        self.assertFalse(htpasswd.sha1_check(b'notpassword', hashed))

    def test_plain_check(self):
        self.assertTrue(htpasswd.plain_check('password', 'password'))
        self.assertFalse(htpasswd.plain_check('notpassword', 'password'))

    def test_factory_no_filename_raises(self):
        self.assertRaises(ValueError, htpasswd.make_plugin)

    def test_factory_no_check_fn_raises(self):
        self.assertRaises(ValueError, htpasswd.make_plugin, 'foo')

    def test_factory(self):
        plugin = htpasswd.make_plugin(
            'foo',
            'repoze.who.plugins.htpasswd:crypt_check',
        )
        self.assertEqual(plugin.filename, 'foo')
        self.assertEqual(plugin.check, htpasswd.crypt_check)
