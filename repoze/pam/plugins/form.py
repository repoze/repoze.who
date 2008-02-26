from paste.httpheaders import CONTENT_LENGTH
from paste.httpheaders import CONTENT_TYPE

from paste.request import parse_dict_querystring
from paste.request import parse_formvars

from zope.interface import implements

from repoze.pam.interfaces import IChallenger
from repoze.pam.interfaces import IIdentifier

_DEFAULT_FORM = """
<html>
<head>
  <title>Login Form</title>
</head>
<body>
  <div>
     <b>Log In</b>
  </div>
  <br/>
  <form method="POST" action="?__do_login=true">
    <table border="0">
    <tr>
      <td>User Name</td>
      <td><input type="text" name="login"></input></td>
    </tr>
    <tr>
      <td>Password</td>
      <td><input type="password" name="password"></input></td>
    </tr>
    <tr>
      <td></td>
      <td><input type="submit" name="submit" value="Log In"/></td>
    </tr>
    </table>
  </form>
  <pre>
  %s
  </pre>
</body>
</html>
"""

class FormPlugin(object):

    implements(IChallenger, IIdentifier)
    
    def __init__(self, login_form_qs, rememberer_name):
        self.login_form_qs = login_form_qs
        # rememberer_name is the name of another configured plugin which
        # implements IIdentifier, to handle remember and forget duties
        # (ala a cookie plugin or a session plugin)
        self.rememberer_name = rememberer_name

    # IIdentifier
    def identify(self, environ):
        query = parse_dict_querystring(environ)
        # If the extractor finds a special query string on any request,
        # it will attempt to find the values in the input body.
        if query.get(self.login_form_qs): 
            form = parse_formvars(environ)
            from StringIO import StringIO
            # XXX we need to replace wsgi.input because we've read it
            # this smells funny
            environ['wsgi.input'] = StringIO()
            form.update(query)
            try:
                login = form['login']
                password = form['password']
            except KeyError:
                return {}
            return {'login':login, 'password':password}

        return {}

    def _get_rememberer(self, environ):
        rememberer = environ['repoze.pam.plugins'][self.rememberer_name]
        return rememberer

    # IIdentifier
    def remember(self, environ, identity):
        rememberer = self._get_rememberer(environ)
        return rememberer.remember(environ, identity)

    # IIdentifier
    def forget(self, environ, identity):
        rememberer = self._get_rememberer(environ)
        return rememberer.forget(environ, identity)

    # IChallenger
    def challenge(self, environ, status, app_headers, forget_headers):
        # heck yeah.
        def auth_form(environ, start_response):
            import pprint
            form = _DEFAULT_FORM % pprint.pformat(environ)
            content_length = CONTENT_LENGTH.tuples(str(len(form)))
            content_type = CONTENT_TYPE.tuples('text/html')
            headers = content_length + content_type + forget_headers
            start_response('200 OK', headers)
            return [form]

        return auth_form

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))

def make_plugin(pam_conf, login_form_qs='__do_login', rememberer_name=None):
    if rememberer_name is None:
        raise ValueError(
            'must include rememberer key (name of another IIdentifier plugin)')
    plugin = FormPlugin(login_form_qs, rememberer_name)
    return plugin

