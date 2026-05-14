import codecs
import datetime
import hashlib
import os
import time
from urllib.parse import parse_qsl
from urllib.parse import urlencode
from wsgiref import handlers as wsgiref_handlers

from zope.interface import implementer

from repoze.who import _auth_tkt as auth_tkt
from repoze.who import _helpers
from repoze.who import interfaces
from repoze.who import utils

_UTCNOW = None  # unit tests can replace
def _utcnow():  #pragma NO COVERAGE
    if _UTCNOW is not None:
        return _UTCNOW
    # We use 'datetime.timezone.utc' for compat w/ Python 3.10.
    return datetime.datetime.now(datetime.timezone.utc)  # noqa: UP017

class ReissueTimeMustBeLowerThanTimeout(ValueError):
    def __init__(self, reissue_time, timeout):
        self.reissue_time = reissue_time
        self.timeout = timeout
        super().__init__(
            'When timeout is specified, reissue_time must be '
            'set to a lower value'
        )

class ExactlyOneOfSecretOrSecretFile(ValueError):
    def __init__(self):
        super().__init__(
            "Pass exactly one of 'secret' or 'secretfile'"
        )

class InvalidSecretfile(ValueError):
    def __init__(self, secretfile):
        self.secretfile = secretfile
        super().__init__(f"No such 'secretfile': {secretfile}")

class InvalidDigestAlgo(ValueError):
    def __init__(self, digest_algo):
        self.digest_algo = digest_algo
        super().__init__(f"No such digest algorithm: {digest_algo}")

@implementer(interfaces.IIdentifier, interfaces.IAuthenticator)
class AuthTktCookiePlugin:

    userid_typename = 'userid_type'
    userid_type_decoders = {
        'int': int,
        'unicode': lambda x: codecs.utf_8_decode(x)[0],
    }
    userid_type_encoders = {
        int: ('int', str),
    }
 
    def __init__(
        self,
        secret,
        cookie_name='auth_tkt',
        secure=False,
        include_ip=False,
        timeout=None,
        reissue_time=None,
        userid_checker=None,
        digest_algo=auth_tkt.DEFAULT_DIGEST,
        samesite=None,
    ):
        self.secret = secret
        self.cookie_name = cookie_name
        self.include_ip = include_ip
        self.secure = secure

        if timeout and ( (not reissue_time) or (reissue_time > timeout) ):
            raise ReissueTimeMustBeLowerThanTimeout(reissue_time, timeout)

        self.timeout = timeout
        self.reissue_time = reissue_time
        self.userid_checker = userid_checker
        self.digest_algo = digest_algo
        self.samesite = samesite

    # IIdentifier
    def identify(self, environ):
        cookies = _helpers.get_cookies(environ)
        cookie = cookies.get(self.cookie_name)

        if cookie is None or not cookie.value:
            return None

        if self.include_ip:
            remote_addr = environ['REMOTE_ADDR']
        else:
            remote_addr = '0.0.0.0'
        
        try:
            timestamp, userid, tokens, user_data = auth_tkt.parse_ticket(
                self.secret, cookie.value, remote_addr, self.digest_algo)
        except auth_tkt.BadTicket:
            return None

        if self.timeout and ( (timestamp + self.timeout) < time.time() ):
            return None

        user_data_dict = dict(parse_qsl(user_data))
        userid_type = user_data_dict.get(self.userid_typename)
        if userid_type:
            decoder = self.userid_type_decoders.get(userid_type)
            if decoder:
                userid = decoder(userid)
            
        environ['REMOTE_USER_TOKENS'] = tokens
        environ['REMOTE_USER_DATA'] = user_data
        environ['AUTH_TYPE'] = 'cookie'

        identity = {}
        identity['timestamp'] = timestamp
        identity['repoze.who.plugins.auth_tkt.userid'] = userid
        identity['tokens'] = tokens
        identity['userdata'] = user_data_dict
        return identity

    # IIdentifier
    def forget(self, environ, identity):
        # return a set of expires Set-Cookie headers
        return self._get_cookies(environ, 'INVALID', 0)
    
    # IIdentifier
    def remember(self, environ, identity):
        if self.include_ip:
            remote_addr = environ['REMOTE_ADDR']
        else:
            remote_addr = '0.0.0.0'

        cookies = _helpers.get_cookies(environ)
        existing = cookies.get(self.cookie_name)
        old_cookie_value = getattr(existing, 'value', None)
        max_age = identity.get('max_age', None)

        timestamp, userid, tokens, userdata = None, '', (), ''

        if old_cookie_value:
            try:
                timestamp,userid,tokens,userdata = auth_tkt.parse_ticket(
                    self.secret, old_cookie_value, remote_addr,
                    self.digest_algo)
            except auth_tkt.BadTicket:
                pass
        tokens = tuple(tokens)

        who_userid = identity['repoze.who.userid']
        who_tokens = tuple(identity.get('tokens', ()))
        who_userdata_dict = identity.get('userdata', {})

        encoding_data = self.userid_type_encoders.get(type(who_userid))
        if encoding_data:
            encoding, encoder = encoding_data
            who_userid = encoder(who_userid)
            who_userdata_dict[self.userid_typename] = encoding

        who_userdata = urlencode(who_userdata_dict)

        old_data = (userid, tokens, userdata)
        new_data = (who_userid, who_tokens, who_userdata)

        if old_data != new_data or (self.reissue_time and
                ( (timestamp + self.reissue_time) < time.time() )):
            ticket = auth_tkt.AuthTicket(
                self.secret,
                who_userid,
                remote_addr,
                tokens=who_tokens,
                user_data=who_userdata,
                cookie_name=self.cookie_name,
                secure=self.secure,
                digest_algo=self.digest_algo)
            new_cookie_value = ticket.cookie_value()
            
            if old_cookie_value != new_cookie_value:
                # return a set of Set-Cookie headers
                return self._get_cookies(environ, new_cookie_value, max_age)

    # IAuthenticator
    def authenticate(self, environ, identity):
        userid = identity.get('repoze.who.plugins.auth_tkt.userid')
        if userid is None:
            return None
        if self.userid_checker and not self.userid_checker(userid):
            return None
        identity['repoze.who.userid'] = userid
        return userid

    def _get_cookies(self, environ, value, max_age=None):
        if max_age is not None:
            max_age = int(max_age)
            later = _utcnow() + datetime.timedelta(seconds=max_age)
            # Wdy, DD-Mon-YY HH:MM:SS GMT
            expires = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (  # noqa: UP031
                # Locale-independent, RFC-2616
                wsgiref_handlers._weekdayname[later.weekday()],
                later.day,
                # Locale-independent, RFC-2616
                wsgiref_handlers._monthname[later.month],
                later.year,
                later.hour,
                later.minute,
                later.second,
            )
            # the Expires header is *required* at least for IE7 (IE7 does
            # not respect Max-Age)
            max_age = f"; Max-Age={max_age}; Expires={expires}"
        else:
            max_age = ''

        secure = ''
        if self.secure:
            secure = '; secure; HttpOnly'

        if self.samesite:
            secure += f'; SameSite={self.samesite}'

        cur_domain = environ.get('HTTP_HOST', environ.get('SERVER_NAME'))
        cur_domain = cur_domain.split(':')[0] # drop port
        wild_domain = '.' + cur_domain
        cookies = [
            (
                'Set-Cookie',
                f'{self.cookie_name}="{value}"; '
                f'Path=/{max_age}{secure}'
            ),
            (
                'Set-Cookie',
                f'{self.cookie_name}="{value}"; Path=/; '
                f'Domain={cur_domain}{max_age}{secure}'
            ),
            (
                'Set-Cookie',
                f'{self.cookie_name}="{value}"; Path=/; '
                f'Domain={wild_domain}{max_age}{secure}',
            ),
        ]
        return cookies

    def __repr__(self):  # pragma: NO COVER
        return f'<{self.__class__.__name__} {id(self)}>'

def _bool(value):
    if isinstance(value, str):
        return value.lower() in ('yes', 'true', '1')
    return value

def make_plugin(secret=None,
                secretfile=None,
                cookie_name='auth_tkt',
                secure=False,
                include_ip=False,
                timeout=None,
                reissue_time=None,
                userid_checker=None,
                digest_algo=auth_tkt.DEFAULT_DIGEST,
               ):
    if (secret is None and secretfile is None):
        raise ExactlyOneOfSecretOrSecretFile()

    if (secret is not None and secretfile is not None):
        raise ExactlyOneOfSecretOrSecretFile()

    if secretfile:
        secretfile = os.path.abspath(os.path.expanduser(secretfile))

        if not os.path.exists(secretfile):
            raise InvalidSecretfile(secretfile)

        with open(secretfile) as f:
            secret = f.read().strip()

    if timeout:
        timeout = int(timeout)

    if reissue_time:
        reissue_time = int(reissue_time)

    if userid_checker is not None:
        userid_checker = utils.resolveDotted(userid_checker)

    if isinstance(digest_algo, str):
        try:
            digest_algo = getattr(hashlib, digest_algo)
        except AttributeError:
            raise InvalidDigestAlgo(digest_algo) from None

    plugin = AuthTktCookiePlugin(secret,
                                 cookie_name,
                                 _bool(secure),
                                 _bool(include_ip),
                                 timeout,
                                 reissue_time,
                                 userid_checker,
                                 digest_algo,
                                 )
    return plugin

