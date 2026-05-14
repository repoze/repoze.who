import hashlib

from zope.interface import implementer

from repoze.who import interfaces
from repoze.who import utils


class QueryRequired(ValueError):
    def __init__(self):
        super().__init__("'query' required.")


class ConnFactoryRequired(ValueError):
    def __init__(self):
        super().__init__("'conn_factory' required.")


class InvalidConnFactory(ValueError):
    def __init__(self, conn_factory):
        self.conn_factory = conn_factory
        super().__init__(f"Invalid 'conn_factory': {conn_factory}")


def default_password_compare(cleartext_password, stored_password_hash):
    # the stored password is stored as '{SHA}<SHA hexdigest>'.
    # or as a cleartext password (no {SHA} prefix)

    if stored_password_hash.startswith("{SHA}"):
        stored_password_hash = stored_password_hash[5:]

        if not isinstance(cleartext_password, bytes):
            cleartext_password = cleartext_password.encode("utf-8")

        digest = hashlib.sha1(cleartext_password).hexdigest()
    else:
        digest = cleartext_password

    if stored_password_hash == digest:
        return True

    return False


def make_psycopg_conn_factory(**kw):
    # convenience (I always seem to use Postgres)
    def conn_factory():  # pragma NO COVERAGE
        import psycopg2  # pragma NO COVERAGE

        return psycopg2.connect(kw["repoze.who.dsn"])  # pragma NO COVERAGE

    return conn_factory  # pragma NO COVERAGE


@implementer(interfaces.IAuthenticator)
class SQLAuthenticatorPlugin:
    def __init__(self, query, conn_factory, compare_fn):
        # statement should be pyformat dbapi binding-style, e.g.
        # "select user_id, password from users where login=%(login)s"
        self.query = query
        self.conn_factory = conn_factory
        self.compare_fn = compare_fn or default_password_compare
        self.conn = None

    # IAuthenticator
    def authenticate(self, environ, identity):
        if "login" not in identity:
            return None
        if not self.conn:
            self.conn = self.conn_factory()
        curs = self.conn.cursor()
        curs.execute(self.query, identity)
        result = curs.fetchone()
        curs.close()
        if result:
            user_id, password = result
            if self.compare_fn(identity["password"], password):
                return user_id


@implementer(interfaces.IMetadataProvider)
class SQLMetadataProviderPlugin:
    def __init__(self, name, query, conn_factory, filter):
        self.name = name
        self.query = query
        self.conn_factory = conn_factory
        self.filter = filter
        self.conn = None

    # IMetadataProvider
    def add_metadata(self, environ, identity):
        if self.conn is None:
            self.conn = self.conn_factory()
        curs = self.conn.cursor()
        # can't use dots in names in python string formatting :-(
        identity["__userid"] = identity["repoze.who.userid"]
        curs.execute(self.query, identity)
        result = curs.fetchall()
        if self.filter:
            result = self.filter(result)
        curs.close()
        del identity["__userid"]
        identity[self.name] = result


def make_authenticator_plugin(
    query,
    conn_factory=None,
    compare_fn=None,
    **kw,
):
    if query is None:
        raise QueryRequired()

    if conn_factory is None:
        raise ConnFactoryRequired()

    try:
        conn_factory = utils.resolveDotted(conn_factory)(**kw)
    except Exception as why:
        raise InvalidConnFactory(conn_factory) from why

    if compare_fn is not None:
        compare_fn = utils.resolveDotted(compare_fn)

    return SQLAuthenticatorPlugin(query, conn_factory, compare_fn)


def make_metadata_plugin(
    name,
    query,
    conn_factory=None,
    filter=None,
    **kw,
):
    if query is None:
        raise QueryRequired()

    if conn_factory is None:
        raise ConnFactoryRequired()
    try:
        conn_factory = utils.resolveDotted(conn_factory)(**kw)
    except Exception as why:
        raise InvalidConnFactory(conn_factory) from why

    if filter is not None:
        filter = utils.resolveDotted(filter)

    return SQLMetadataProviderPlugin(name, query, conn_factory, filter)
