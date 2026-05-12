try:
    import crypt
except ImportError:
    # Note: the crypt module is deprecated since Python 3.11
    # and will be removed in Python 3.13.
    # win32 does not have a crypt library at all.
    HAS_CRYPT = False
else:
    HAS_CRYPT = True
import itertools
import warnings

from zope.interface import implementer

from repoze.who.interfaces import IAuthenticator
from repoze.who.utils import resolveDotted


def _padding_for_file_lines():
    yield 'aaaaaa:bbbbbb'


@implementer(IAuthenticator)
class HTPasswdPlugin(object):


    def __init__(self, filename, check):
        self.filename = filename
        self.check = check

    # IAuthenticatorPlugin
    def authenticate(self, environ, identity):
        # NOW HEAR THIS!!!
        #
        # This method is *intentionally* slower than would be ideal because
        # it is trying to avoid leaking information via timing attacks
        # (number of users, length of user IDs, length of passwords, etc.).
        #
        # Do *not* try to optimize anything away here.
        try:
            login = identity['login']
            password = identity['password']
        except KeyError:
            return None

        if hasattr(self.filename, 'seek'):
            # assumed to have a readline
            self.filename.seek(0)
            f = self.filename
            must_close = False
        else:
            try:
                f = open(self.filename, 'r')
                must_close = True
            except IOError:
                environ['repoze.who.logger'].warn('could not open htpasswd '
                                                  'file %s' % self.filename)
                return None

        result = None
        maybe_user = None
        to_check = 'ABCDEF0123456789'

        # Try not to reveal how many users we have.
        # XXX:  the max count here should be configurable ;(
        lines = itertools.chain(f, _padding_for_file_lines())
        for line in itertools.islice(lines, 0, 1000):
            try:
                username, hashed = line.rstrip().split(':', 1)
            except ValueError:
                continue
            if _same_string(username, login):
                # Don't bail early:  leaks information!!
                maybe_user = username
                to_check = hashed

        if must_close:
            f.close()

        # Check *something* here, to mitigate a timing attack.
        password_ok = self.check(password, to_check)

        # Check our flags:  if both are OK, we found a match.
        if password_ok and maybe_user:
            result = maybe_user

        return result

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__,
                            id(self)) #pragma NO COVERAGE

PADDING = ' ' * 1000

def _same_string(x, y):
    # Attempt at isochronous string comparison.
    mismatches = filter(None, [a != b for a, b, ignored
                                    in itertools.zip_longest(x, y, PADDING)])
    if type(mismatches) != list: #pragma NO COVER Python >= 3.0
        mismatches = list(mismatches)
    return len(mismatches) == 0


if not HAS_CRYPT:

    class CryptModuleNotImportable(RuntimeError):
        def __init__(self):
            super().__init__(
                "'crypt' module is not importable. "
                "Try 'bcrypt.checkpw' instead?"
            )

def crypt_check(password, hashed):

    if not HAS_CRYPT:
        raise CryptModuleNotImportable()

    warnings.warn(
        "'crypt' module is deprecated -- try 'bcrypt.checkpw' instead?"
    )
    salt = hashed[:2]
    return _same_string(hashed, crypt.crypt(password, salt))


def sha1_check(password, hashed):
    from hashlib import sha1
    from base64 import standard_b64encode
    from repoze.who._helpers import must_encode
    b_password = must_encode(password)
    b_sha1_digest = sha1(b_password).digest()
    b_b64_sha1_digest = standard_b64encode(b_sha1_digest)
    return _same_string(hashed, b"{SHA}" + b_b64_sha1_digest)

def plain_check(password, hashed):
    return _same_string(password, hashed)


def make_plugin(filename=None, check_fn=None):
    if filename is None:
        raise ValueError('filename must be specified')
    if check_fn is None:
        raise ValueError('check_fn must be specified')
    check = resolveDotted(check_fn)
    return HTPasswdPlugin(filename, check)
