from zope.interface import implements

from repoze.pam.interfaces import IAuthenticatorPlugin
from repoze.pam.utils import resolveDotted

class HTPasswdAuthenticator(object):

    implements(IAuthenticatorPlugin)

    def __init__(self, filename, check):
        self.filename = filename
        self.check = check

    # IAuthenticatorPlugin
    def authenticate(self, environ, credentials):
        try:
            login = credentials['login']
            password = credentials['password']
        except KeyError:
            return False

        if hasattr(self.filename, 'seek'):
            # assumed to have a readline
            self.filename.seek(0)
            f = self.filename
        else:
            try:
                f = open(self.filename, 'r')
            except IOError:
                return False

        for line in f:
            try:
                username, hashed = line.rstrip().split(':', 1)
            except ValueError:
                continue
            if username == login:
                return self.check(password, hashed)
        return False

def check_crypted(password, hashed):
    from crypt import crypt
    salt = hashed[:2]
    return hashed == crypt(password, salt)

def make_plugin(pam_conf, filename, check_fn):
    check = resolveDotted(check_fn)
    return HTPasswdAuthenticator(filename, check)

    
