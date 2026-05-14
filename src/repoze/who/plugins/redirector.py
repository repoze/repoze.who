from urllib import parse as urllib_parse

from webob import exc as webob_exc
from zope.interface import implementer

from repoze.who import _helpers
from repoze.who import interfaces


class LoginUrlRequired(ValueError):
    def __init__(self):
        super().__init__("'login_url' required.")


class BothReasonHeaderAndReasonParamOrNeither(ValueError):
    def __init__(self):
        super().__init__(
            "Must supply both 'reason_header' and 'reason_param', "
            "or neither one."
        )


@implementer(interfaces.IChallenger)
class RedirectorPlugin:
    """Plugin for issuing challenges as redirects to a configured URL.

    o If the ``reason_param`` option is configured, and the application has
      supplied an ``X-Authorization-Failure-Reason`` header, the plugin
      includes that reason in the query string of the redirected URL.
    """

    def __init__(
        self,
        login_url,
        came_from_param="came_from",
        reason_param="reason",
        reason_header="X-Authorization-Failure-Reason",
    ):
        self.login_url = login_url
        self.came_from_param = came_from_param

        if (reason_param is None and reason_header is not None) or (
            reason_param is not None and reason_header is None
        ):
            raise BothReasonHeaderAndReasonParamOrNeither()

        self.reason_param = reason_param
        self.reason_header = reason_header
        self._login_url_parts = list(urllib_parse.urlparse(login_url))

    # IChallenger
    def challenge(self, environ, status, app_headers, forget_headers):
        if self.reason_param is not None or self.came_from_param is not None:
            url_parts = self._login_url_parts[:]
            query = url_parts[4]
            query_elements = urllib_parse.parse_qs(query)
            if self.reason_param is not None:
                reason = _helpers.header_value(app_headers, self.reason_header)
                if reason:
                    query_elements[self.reason_param] = reason
            if self.came_from_param is not None:
                query_elements[self.came_from_param] = _helpers.construct_url(
                    environ
                )
            url_parts[4] = urllib_parse.urlencode(query_elements, doseq=True)
            login_url = urllib_parse.urlunparse(url_parts)
        else:
            login_url = self.login_url
        headers = [("Location", login_url)] + forget_headers
        cookies = [
            (h, v) for (h, v) in app_headers if h.lower() == "set-cookie"
        ]
        headers += cookies
        return webob_exc.HTTPFound(headers=headers)


def make_plugin(
    login_url,
    came_from_param=None,
    reason_param=None,
    reason_header=None,
):
    if login_url in ("", b"", None):
        raise LoginUrlRequired()

    if reason_header is None and reason_param is not None:
        reason_header = "X-Authorization-Failure-Reason"

    return RedirectorPlugin(
        login_url,
        came_from_param=came_from_param,
        reason_param=reason_param,
        reason_header=reason_header,
    )
