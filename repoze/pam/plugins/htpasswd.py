from zope.interface import implements

from repoze.pam.interfaces import IAuthenticator
from repoze.pam.utils import resolveDotted

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
                return None

        for line in f:
            try:
                username, hashed = line.rstrip().split(':', 1)
            except ValueError:
                continue
            if username == login:
                if self.check(password, hashed):
                    return username
        return None

def crypt_check(password, hashed):
    from crypt import crypt
    salt = hashed[:2]
    return hashed == crypt(password, salt)

def make_plugin(pam_conf, filename=None, check_fn=None):
    if filename is None:
        raise ValueError('filename must be specified')
    if check_fn is None:
        raise ValueError('check_fn must be specified')
    check = resolveDotted(check_fn)
    return HTPasswdPlugin(filename, check)

    
