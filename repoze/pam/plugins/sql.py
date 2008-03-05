from zope.interface import implements

from repoze.pam.interfaces import IAuthenticator

def default_password_compare(cleartext_password, stored_password_hash):
    import sha

    # the stored password is stored as '{SHA}<SHA hexdigest>'.
    # or as a cleartext password (no {SHA} prefix)

    if stored_password_hash.startswith('{SHA}'):
        stored_password_hash = stored_password_hash[5:]
        digest = sha.new(cleartext_password).hexdigest()
    else:
        digest = cleartext_password
        
    if stored_password_hash == digest:
        return True

    return False

def psycopg_connect(dsn):
    # convenience (I always seem to use Postgres)
    import psycopg2
    return psycopg2.connect(dsn)

class SQLAuthenticatorPlugin:
    implements(IAuthenticator)

    def __init__(self, dsn, statement, compare_fn, conn_factory):
        self.dsn = dsn
        # statement should be pyformat dbapi binding-style, e.g.
        # "select user_id, password from users where login=%(login)s"
        self.statement = statement
        self.compare_fn = compare_fn or default_password_compare
        self.conn_factory = conn_factory or psycopg_connect
        self.conn = None

    def _connect(self):
        return self.conn_factory(self.dsn)

    # IAuthenticator
    def authenticate(self, environ, identity):
        if not self.conn:
            self.conn = self._connect()
        curs = self.conn.cursor()
        curs.execute(self.statement, identity)
        result = curs.fetchone()
        curs.close()
        if result:
            user_id, password = result
            if self.compare_fn(identity['password'], password):
                return user_id

def make_plugin(pam_conf, dsn=None, statement=None, compare_fn=None,
                conn_factory=None):
    from repoze.pam.utils import resolveDotted
    if dsn is None:
        raise ValueError('dsn must be specified')
    if statement is None:
        raise ValueError('statement must be specified')
    if compare_fn is not None:
        compare_fn = resolveDotted(compare_fn)
    if conn_factory is not None:
        conn_factory = resolveDotted(conn_factory)
    return SQLAuthenticatorPlugin(dsn, statement, compare_fn, conn_factory)

    
