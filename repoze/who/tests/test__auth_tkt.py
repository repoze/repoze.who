import unittest

class AuthTicketTests(unittest.TestCase):

    def _getTargetClass(self):
        from .._auth_tkt import AuthTicket
        return AuthTicket

    def _makeOne(self, *args, **kw):
        return self._getTargetClass()(*args, **kw)

    def test_ctor_defaults(self):
        from .. import _auth_tkt
        with _Monkey(_auth_tkt, time_mod=_Timemod):
            tkt = self._makeOne('SEEKRIT', 'USERID', '1.2.3.4')
        self.assertEqual(tkt.secret, 'SEEKRIT')
        self.assertEqual(tkt.userid, 'USERID')
        self.assertEqual(tkt.ip, '1.2.3.4')
        self.assertEqual(tkt.tokens, '')
        self.assertEqual(tkt.user_data, '')
        self.assertEqual(tkt.time, _WHEN)
        self.assertEqual(tkt.cookie_name, 'auth_tkt')
        self.assertEqual(tkt.secure, False)

    def test_ctor_explicit(self):
        tkt = self._makeOne('SEEKRIT', 'USERID', '1.2.3.4', tokens=('a', 'b'),
                            user_data='DATA', time=_WHEN,
                            cookie_name='oatmeal', secure=True)
        self.assertEqual(tkt.secret, 'SEEKRIT')
        self.assertEqual(tkt.userid, 'USERID')
        self.assertEqual(tkt.ip, '1.2.3.4')
        self.assertEqual(tkt.tokens, 'a,b')
        self.assertEqual(tkt.user_data, 'DATA')
        self.assertEqual(tkt.time, _WHEN)
        self.assertEqual(tkt.cookie_name, 'oatmeal')
        self.assertEqual(tkt.secure, True)

    def test_digest(self):
        from .._auth_tkt import calculate_digest
        tkt = self._makeOne('SEEKRIT', 'USERID', '1.2.3.4', tokens=('a', 'b'),
                            user_data='DATA', time=_WHEN,
                            cookie_name='oatmeal', secure=True)
        digest = calculate_digest('1.2.3.4', _WHEN, 'SEEKRIT', 'USERID',
                                  'a,b', 'DATA')
        self.assertEqual(tkt.digest(), digest)

    def test_cookie_value_wo_tokens_or_userdata(self):
        from .._auth_tkt import calculate_digest
        tkt = self._makeOne('SEEKRIT', 'USERID', '1.2.3.4', time=_WHEN)
        digest = calculate_digest('1.2.3.4', _WHEN, 'SEEKRIT', 'USERID', '', '')
        self.assertEqual(tkt.cookie_value(),
                         '%s%08xUSERID!' % (digest, _WHEN))

    def test_cookie_value_w_tokens_and_userdata(self):
        from .._auth_tkt import calculate_digest
        tkt = self._makeOne('SEEKRIT', 'USERID', '1.2.3.4', tokens=('a', 'b'),
                            user_data='DATA', time=_WHEN)
        digest = calculate_digest('1.2.3.4', _WHEN, 'SEEKRIT', 'USERID',
                                  'a,b', 'DATA')
        self.assertEqual(tkt.cookie_value(),
                         '%s%08xUSERID!a,b!DATA' % (digest, _WHEN))

    def test_cookie_not_secure_wo_tokens_or_userdata(self):
        from .._auth_tkt import calculate_digest
        from .._compat import encodestring
        tkt = self._makeOne('SEEKRIT', 'USERID', '1.2.3.4', time=_WHEN,
                            cookie_name='oatmeal')
        digest = calculate_digest('1.2.3.4', _WHEN, 'SEEKRIT', 'USERID', '', '')
        cookie = tkt.cookie()
        self.assertEqual(cookie['oatmeal'].value,
                         encodestring('%s%08xUSERID!' % (digest, _WHEN)
                                     ).strip())
        self.assertEqual(cookie['oatmeal']['path'], '/')
        self.assertEqual(cookie['oatmeal']['secure'], '')

    def test_cookie_secure_w_tokens_and_userdata(self):
        from .._auth_tkt import calculate_digest
        from .._compat import encodestring
        tkt = self._makeOne('SEEKRIT', 'USERID', '1.2.3.4', tokens=('a', 'b'),
                            user_data='DATA', time=_WHEN,
                            cookie_name='oatmeal', secure=True)
        digest = calculate_digest('1.2.3.4', _WHEN, 'SEEKRIT', 'USERID',
                                  'a,b', 'DATA')
        cookie = tkt.cookie()
        self.assertEqual(cookie['oatmeal'].value,
                         encodestring('%s%08xUSERID!a,b!DATA' % (digest, _WHEN)
                                     ).strip())
        self.assertEqual(cookie['oatmeal']['path'], '/')
        self.assertEqual(cookie['oatmeal']['secure'], 'true')
 


_WHEN = 1234567
class _Timemod(object):
    @staticmethod
    def time():
        return _WHEN


class _Monkey(object):

    def __init__(self, module, **replacements):
        self.module = module
        self.orig = {}
        self.replacements = replacements
        
    def __enter__(self):
        for k, v in self.replacements.items():
            orig = getattr(self.module, k, self)
            if orig is not self:
                self.orig[k] = orig
            setattr(self.module, k, v)

    def __exit__(self, *exc_info):
        for k, v in self.replacements.items():
            if k in self.orig:
                setattr(self.module, k, self.orig[k])
            else: #pragma NO COVERSGE
                delattr(self.module, k)
