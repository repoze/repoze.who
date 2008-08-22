from codecs import utf_8_decode
from codecs import utf_8_encode

from paste.request import get_cookies
from paste.auth import auth_tkt

from zope.interface import implements

from repoze.who.interfaces import IIdentifier

class AuthTktCookiePlugin(object):

    implements(IIdentifier)

    userid_type_decoders = {
        'int':int,
        'unicode':lambda x: utf_8_decode(x)[0],
        }

    userid_type_encoders = {
        int: ('int', str),
        long: ('int', str),
        unicode: ('unicode', lambda x: utf_8_encode(x)[0]),
        }
    
    def __init__(self, secret, cookie_name='auth_tkt',
                 secure=False, include_ip=False):
        self.secret = secret
        self.cookie_name = cookie_name
        self.include_ip = include_ip
        self.secure = secure
        self.include_ip = include_ip

    # IIdentifier
    def identify(self, environ):
        cookies = get_cookies(environ)
        cookie = cookies.get(self.cookie_name)

        if cookie is None or not cookie.value:
            return None

        if self.include_ip:
            remote_addr = environ['REMOTE_ADDR']
        else:
            remote_addr = '0.0.0.0'
        
        try:
            timestamp, userid, tokens, user_data = auth_tkt.parse_ticket(
                self.secret, cookie.value, remote_addr)
        except auth_tkt.BadTicket:
            return None

        userid_typename = 'userid_type:'
        user_data_info = user_data.split('|')
        for datum in filter(None, user_data_info):
            if datum.startswith(userid_typename):
                userid_type = datum[len(userid_typename):]
                decoder = self.userid_type_decoders.get(userid_type)
                if decoder:
                    userid = decoder(userid)
            
        if environ.get('REMOTE_USER_TOKENS'):
            # We want to add tokens/roles to what's there:
            tokens = environ['REMOTE_USER_TOKENS'] + ',' + tokens
        environ['REMOTE_USER_TOKENS'] = tokens
        environ['REMOTE_USER_DATA'] = user_data
        environ['AUTH_TYPE'] = 'cookie'
        identity = {}
        identity['timestamp'] = timestamp
        identity['repoze.who.userid'] = userid
        identity['tokens'] = tokens
        identity['userdata'] = user_data
        return identity

    # IIdentifier
    def forget(self, environ, identity):
        # return a expires Set-Cookie header
        cur_domain = environ.get('HTTP_HOST', environ.get('SERVER_NAME'))
        wild_domain = '.' + cur_domain
        cookies = [
            ('Set-Cookie', '%s=""; Path=/' % self.cookie_name),
            ('Set-Cookie', '%s=""; Path=/; Domain=%s' %
             (self.cookie_name, cur_domain)),
            ('Set-Cookie', '%s=""; Path=/; Domain=%s' %
             (self.cookie_name, wild_domain)),
            ]
        return cookies
    
    # IIdentifier
    def remember(self, environ, identity):
        if self.include_ip:
            remote_addr = environ['REMOTE_ADDR']
        else:
            remote_addr = '0.0.0.0'

        cookies = get_cookies(environ)
        old_cookie = cookies.get(self.cookie_name)
        existing = cookies.get(self.cookie_name)
        old_cookie_value = getattr(existing, 'value', None)

        timestamp, userid, tokens, userdata = None, '', '', ''

        if old_cookie_value:
            try:
                timestamp,userid,tokens,userdata = auth_tkt.parse_ticket(
                    self.secret, old_cookie_value, remote_addr)
            except auth_tkt.BadTicket:
                pass

        who_userid = identity['repoze.who.userid']
        who_tokens = identity.get('tokens', '')
        who_userdata = identity.get('userdata', '')

        encoding_data = self.userid_type_encoders.get(type(who_userid))
        if encoding_data:
            encoding, encoder = encoding_data
            who_userid = encoder(who_userid)
            who_userdata = 'userid_type:%s' % encoding
        
        if not isinstance(tokens, basestring):
            tokens = ','.join(tokens)
        if not isinstance(who_tokens, basestring):
            who_tokens = ','.join(who_tokens)
        old_data = (userid, tokens, userdata)
        new_data = (who_userid, who_tokens, who_userdata)

        if old_data != new_data:
            ticket = auth_tkt.AuthTicket(
                self.secret,
                who_userid,
                remote_addr,
                tokens=who_tokens,
                user_data=who_userdata,
                cookie_name=self.cookie_name,
                secure=self.secure)
            new_cookie_value = ticket.cookie_value()
            if old_cookie_value != new_cookie_value:
                # return a Set-Cookie header
                set_cookie = '%s=%s; Path=/;' % (self.cookie_name,
                                                 new_cookie_value)
                return [('Set-Cookie', set_cookie)]

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))

def _bool(value):
    if isinstance(value, basestring):
        return value.lower() in ('yes', 'true', '1')
    return value

def make_plugin(secret=None,
                cookie_name='auth_tkt',
                secure=False, include_ip=False):
    if secret is None:
        raise ValueError('secret must not be None')
    plugin = AuthTktCookiePlugin(secret, cookie_name,
                                 _bool(secure), _bool(include_ip))
    return plugin

