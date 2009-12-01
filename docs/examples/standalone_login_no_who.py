# Standalone login application for demo SSO:
# N.B.: this version does *not* use repoze.who at all, but should produce
#       a cookie which repoze.who.plugin.authtkt can use.
import datetime

from paste.auth import auth_tkt
from webob import Request
from webob import Response
from webob.exc import HTTPSeeOther

LOGIN_FORM_TEMPLATE = """\
<html>
<head>
<title> Demo SSO Login </title>
</head>
<body>
<h1> Demo SSO Login </h1>
<p style="color: Red">%(message)s</p>
<form action="#" method="post">
 <input type="hidden" name="came_from" value="%(came_from)s" />
 <fieldset id="login_name_fs">
  <label for="login_name">Login Name</label>
  <input type="text" id="login_name" name="login_name" value="%(login_name)s" />
 </fieldset>
 <fieldset id="password_fs">
  <label for="password">Login Name</label>
  <input type="password" id="password" name="password" />
 </fieldset>
 <input type="submit" name="form.submitted" value="Log In" />
</form>
</body>
</html>
"""

# Clients have to know about these values out-of-band
SECRET = 's33kr1t'
COOKIE_NAME = 'auth_cookie'

MAX_AGE = '3600' # seconds

AUTH = {
    'phred': 'y4bb3d4bb4d00',
    'bharney': 'b3dr0ck',
}

def _validate(login_name, password):
    # Your application's logic goes here
    return AUTH.get(login_name) == password

def _get_cookies(environ, value):

    later = (datetime.datetime.now() +
                datetime.timedelta(seconds=int(MAX_AGE)))
    # Wdy, DD-Mon-YY HH:MM:SS GMT
    expires = later.strftime('%a, %d %b %Y %H:%M:%S')
    # the Expires header is *required* at least for IE7 (IE7 does
    # not respect Max-Age)
    tail = "; Max-Age=%s; Expires=%s" % (MAX_AGE, expires)

    cur_domain = environ.get('HTTP_HOST', environ.get('SERVER_NAME'))
    wild_domain = '.' + cur_domain

    return [('Set-Cookie', '%s="%s"; Path=/; Domain=%s%s'
                        % (COOKIE_NAME, value, wild_domain, tail)),
           ]

def login(environ, start_response):
    request = Request(environ)
    message = ''
    if 'form.submitted' in request.post:
        came_from = request.post['came_from']
        login_name = request.post['login_name']
        password = request.post['password']
        remote_addr = environ['REMOTE_ADDR']
        tokens = userdata = ''
        if _validate(login, password):
            headers = [('Location', came_from)]
            ticket = auth_tkt.AuthTicket(SECRET, login_name, remote_addr,
                                         cookie_name=COOKIE_NAME, secure=True)
            cookies = _get_cookies(environ, ticket.cookie_value())
            return HTTPSeeOther(location=came_from, headers=cookies)
        message = 'Authentication failed'
    else:
        came_from = request.get['came_from']
        login_name = ''

    body = LOGIN_FORM_TEMPLATE % {'message': message,
                                  'came_from': came_from,
                                  'login_name': login_name,
                                 }
    return Response(body=body)
