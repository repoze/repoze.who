import itertools

from zope.interface import implements

from repoze.who.interfaces import IAuthenticator
from repoze.who.utils import resolveDotted


def _padding_for_file_lines():
    yield 'aaaaaa:bbbbbb'


class HTPasswdPlugin(object):

    implements(IAuthenticator)

    def __init__(self, filename, check):
        self.filename = filename
        self.check = check

    # IAuthenticatorPlugin
    def authenticate(self, environ, identity):
        try:
            login = identity['login']
            password = identity['password']
        except KeyError:
            return None

        if hasattr(self.filename, 'seek'):
            # assumed to have a readline
            self.filename.seek(0)
            f = self.filename
        else:
            try:
                f = open(self.filename, 'r')
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

        # Check *something* here, to mitigate a timing attack.
        password_ok = self.check(password, to_check)
        if password_ok and maybe_user:
            result = maybe_user

        return result

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__,
                            id(self)) #pragma NO COVERAGE

PADDING = ' ' * 1000

def _same_string(x, y):
    match = True
    for a, b, ignored in itertools.izip_longest(x, y, PADDING):
        match = a == b and match
    return match

def crypt_check(password, hashed):
    from crypt import crypt
    salt = hashed[:2]
    return _same_string(hashed, crypt(password, salt))

def plain_check(password, hashed):
    return _same_string(password, hashed)


def make_plugin(filename=None, check_fn=None):
    if filename is None:
        raise ValueError('filename must be specified')
    if check_fn is None:
        raise ValueError('check_fn must be specified')
    check = resolveDotted(check_fn)
    return HTPasswdPlugin(filename, check)
