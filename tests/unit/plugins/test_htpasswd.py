import base64
import hashlib
import io
import os
import warnings

import pytest
from zope.interface import verify

from repoze.who import interfaces
from repoze.who.plugins import htpasswd


def _makeEnviron():
    environ = {}
    environ['wsgi.version'] = (1,0)
    return environ

def test_implements():
    verify.verifyClass(interfaces.IAuthenticator, htpasswd.HTPasswdPlugin)

def test_authenticate_nocreds():
    buf = io.StringIO()
    plugin = htpasswd.HTPasswdPlugin(buf, None)
    environ = _makeEnviron()
    creds = {}
    result = plugin.authenticate(environ, creds)
    assert result is None

def test_authenticate_nolines():
    buf = io.StringIO()
    def check(password, hashed):
        return True
    plugin = htpasswd.HTPasswdPlugin(buf, check)
    environ = _makeEnviron()
    creds = {'login':'chrism', 'password':'pass'}
    result = plugin.authenticate(environ, creds)
    assert result is None

def test_authenticate_nousermatch():
    buf = io.StringIO('nobody:foo')
    def check(password, hashed):
        return True
    plugin = htpasswd.HTPasswdPlugin(buf, check)
    environ = _makeEnviron()
    creds = {'login':'chrism', 'password':'pass'}
    result = plugin.authenticate(environ, creds)
    assert result is None

def test_authenticate_match():
    buf = io.StringIO('chrism:pass')
    def check(password, hashed):
        return True
    plugin = htpasswd.HTPasswdPlugin(buf, check)
    environ = _makeEnviron()
    creds = {'login':'chrism', 'password':'pass'}
    result = plugin.authenticate(environ, creds)
    assert result == 'chrism'

def test_authenticate_badline():
    buf = io.StringIO('badline\nchrism:pass')
    def check(password, hashed):
        return True
    plugin = htpasswd.HTPasswdPlugin(buf, check)
    environ = _makeEnviron()
    creds = {'login':'chrism', 'password':'pass'}
    result = plugin.authenticate(environ, creds)
    assert result == 'chrism'

def test_authenticate_filename():
    here = os.path.abspath(os.path.dirname(__file__))
    htpasswd_file = os.path.join(here, 'fixtures', 'test.htpasswd')
    def check(password, hashed):
        return True
    plugin = htpasswd.HTPasswdPlugin(htpasswd_file, check)
    environ = _makeEnviron()
    creds = {'login':'chrism', 'password':'pass'}
    result = plugin.authenticate(environ, creds)
    assert result == 'chrism'

def test_authenticate_bad_filename_logs_to_repoze_who_logger():
    here = os.path.abspath(os.path.dirname(__file__))
    htpasswd_file = os.path.join(
        here,
        'fixtures',
        'test.htpasswd.nonesuch',
    )

    def check(password, hashed): # pragma: no cover
        return True

    plugin = htpasswd.HTPasswdPlugin(htpasswd_file, check)
    environ = _makeEnviron()

    logger = environ['repoze.who.logger'] = DummyLogger()
    creds = {'login':'chrism', 'password':'pass'}

    result = plugin.authenticate(environ, creds)

    assert result is None
    assert len(logger.warnings) == 1
    assert 'could not open htpasswd' in logger.warnings[0]

@pytest.mark.skipif(not htpasswd.HAS_CRYPT, reason="crypt not available")
def test_crypt_check_hit():
    import crypt

    salt = '123'
    hashed = crypt.crypt('password', salt)

    with warnings.catch_warnings(record=True) as logged:
        assert htpasswd.crypt_check('password', hashed)

    assert len(logged) == 1
    record = logged[0]
    assert record.category is UserWarning
    assert "'crypt' module is deprecated" in str(record.message)

@pytest.mark.skipif(not htpasswd.HAS_CRYPT, reason="crypt not available")
def test_crypt_check_miss():
    import crypt

    salt = '123'
    hashed = crypt.crypt('password', salt)

    with warnings.catch_warnings(record=True) as logged:
        assert not htpasswd.crypt_check('notpassword', hashed)

    assert len(logged) == 1
    record = logged[0]
    assert record.category is UserWarning
    assert "'crypt' module is deprecated" in str(record.message)

@pytest.mark.skipif(htpasswd.HAS_CRYPT, reason="crypt available")
def test_crypt_check_gone():
    from repoze.who.plugins.htpasswd import CryptModuleNotImportable

    with pytest.raises(CryptModuleNotImportable):
        htpasswd.crypt_check('password', 'hashed')

def test_sha1_check_w_password_str():
    password = 'password'
    b_password = password.encode("ascii")
    encrypted_string = base64.standard_b64encode(
        hashlib.sha1(
            b_password
        ).digest()
    )
    hashed = b"%s%s" % (b"{SHA}", encrypted_string)

    assert htpasswd.sha1_check(password, hashed)
    assert not htpasswd.sha1_check('notpassword', hashed)

def test_sha1_check_w_password_bytes():

    b_password = b'password'
    encrypted_string = base64.standard_b64encode(
        hashlib.sha1(
            b_password
        ).digest()
    )
    hashed = b"%s%s" % (b"{SHA}", encrypted_string)

    assert htpasswd.sha1_check(b_password, hashed)
    assert not htpasswd.sha1_check(b'notpassword', hashed)

def test_plain_check():
    assert htpasswd.plain_check('password', 'password')
    assert not htpasswd.plain_check('notpassword', 'password')

def test_factory_no_filename_raises():
    with pytest.raises(htpasswd.FilenameRequired):
        htpasswd.make_plugin()

def test_factory_no_check_fn_raises():
    with pytest.raises(htpasswd.CheckFnRequired):
        htpasswd.make_plugin('foo')

def test_factory():
    plugin = htpasswd.make_plugin(
        'foo',
        'repoze.who.plugins.htpasswd:crypt_check',
    )
    assert plugin.filename == 'foo'
    assert plugin.check is htpasswd.crypt_check


class DummyLogger:
    warnings = []

    def warn(self, msg):
        self.warnings.append(msg)
