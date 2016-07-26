from __future__ import absolute_import, division, print_function, \
    with_statement

import base64
import functools
import os
import tornado.web
from abc import ABCMeta, abstractmethod
from tornado import escape, gen, httpclient
from tornado.auth import OAuth2Mixin, AuthError
from tornado.httputil import url_concat
from .tornado_overrides import auth_return_future
from .config import config
from .messages import *

try:
    import urllib.parse as urllib_parse  # py3
except ImportError:
    import urllib as urllib_parse  # py2

MIRACL_COOKIE_TOKEN_KEY = 'miracl_token'
MIRACL_COOKIE_USERDATA_KEY = 'miracl_userdata'
MIRACL_STATE_COOKIE = 'miracl_state'
OAUTH_SETTINGS_KEY = 'miracl'

OAUTH_BASE_URL = config["OAUTH_BASE_URL"]
# TODO: read values from .well-known/openid-configuration
OAUTH_AUTHORIZE_URL = OAUTH_BASE_URL + 'authorize'
OAUTH_ACCESS_TOKEN_URL = OAUTH_BASE_URL + 'oidc/token'
OAUTH_USERINFO_URL = OAUTH_BASE_URL + 'oidc/userinfo'


def set_issuer(issuer):
    global OAUTH_BASE_URL
    global OAUTH_AUTHORIZE_URL, OAUTH_ACCESS_TOKEN_URL, OAUTH_USERINFO_URL
    OAUTH_BASE_URL = issuer
    OAUTH_AUTHORIZE_URL = OAUTH_BASE_URL + 'authorize'
    OAUTH_ACCESS_TOKEN_URL = OAUTH_BASE_URL + 'oidc/token'
    OAUTH_USERINFO_URL = OAUTH_BASE_URL + 'oidc/userinfo'


class MiraclMixin(OAuth2Mixin):
    __metaclass__ = ABCMeta

    _OAUTH_AUTHORIZE_URL = OAUTH_AUTHORIZE_URL
    _OAUTH_ACCESS_TOKEN_URL = OAUTH_ACCESS_TOKEN_URL
    _OAUTH_USERINFO_URL = OAUTH_USERINFO_URL

    @gen.coroutine
    def perform_access_token_request(self):
        state = self.get_secure_cookie(MIRACL_STATE_COOKIE)
        current_state = self.get_argument('state')
        if current_state and state != current_state:
            self.on_auth_failed()
        else:
            access = yield self._get_authenticated_user(
                redirect_uri=self.settings[OAUTH_SETTINGS_KEY][
                    'redirect_uri'],
                code=self.get_argument('code'))
            self.set_secure_cookie(MIRACL_COOKIE_TOKEN_KEY,
                                   access['access_token'])
            yield refresh_user_data(self, access_token=access['access_token'])
            self.on_auth_success(access['access_token'])

    @gen.coroutine
    def _get_authenticated_user(self, redirect_uri, code):
        http = self.get_auth_http_client()
        body = urllib_parse.urlencode({
            'redirect_uri': redirect_uri,
            'code': code,
            'client_id': self.settings[OAUTH_SETTINGS_KEY]['client_id'],
            'client_secret': self.settings[OAUTH_SETTINGS_KEY]['secret'],
            'grant_type': 'authorization_code',
        })

        response = yield http.fetch(
            self._OAUTH_ACCESS_TOKEN_URL,
            method='POST',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            body=body)

        if response.error:
            raise AuthError(MIRACL_MSG_AUTH_ERROR % str(response))
        else:
            args = escape.json_decode(response.body)
            raise gen.Return(args)

    @abstractmethod
    def on_auth_success(self, token):
        pass

    @abstractmethod
    def on_auth_failed(self):
        pass


class MiraclAuthRequestHandler(tornado.web.RequestHandler, MiraclMixin):
    __metaclass__ = ABCMeta

    @gen.coroutine
    def get(self):
        if self.get_argument('code', False):
            yield self.perform_access_token_request()
        else:
            logout(self)
            self.on_auth_failed()


def _gen_rnd_string():
    """ Generates a random string of bytes, base64 encoded """
    length = 12
    string = base64.b64encode(os.urandom(length), altchars=b'-_')
    b64len = 4 * length // 3
    if length % 3 == 1:
        b64len += 2
    elif length % 3 == 2:
        b64len += 3
    return string[0:b64len].decode()


def get_login_url(handler):
    state = _gen_rnd_string()
    handler.set_secure_cookie(MIRACL_STATE_COOKIE, state)

    return url_concat(OAUTH_AUTHORIZE_URL, {
        "redirect_uri": handler.settings[OAUTH_SETTINGS_KEY]['redirect_uri'],
        "client_id": handler.settings[OAUTH_SETTINGS_KEY]['client_id'],
        "response_type": 'code',
        "scope": ' '.join(['openid', 'profile', 'email']),
        "state": state,
        'approval_prompt': 'auto'
    })


def is_authenticated(handler):
    token = handler.get_secure_cookie(MIRACL_COOKIE_TOKEN_KEY)
    return token is not None


@gen.coroutine
def refresh_user_data(handler, access_token=None):
    handler.clear_cookie(MIRACL_COOKIE_USERDATA_KEY)
    data = yield _oauth2_request(handler, OAUTH_USERINFO_URL,
                                 access_token=access_token)
    if data is not None:
        handler.set_secure_cookie(MIRACL_COOKIE_USERDATA_KEY,
                                  escape.json_encode(data))
    else:
        logout(handler)


def logout(handler):
    handler.clear_cookie(MIRACL_COOKIE_TOKEN_KEY)
    handler.clear_cookie(MIRACL_COOKIE_USERDATA_KEY)


def _get_userdata(handler):
    data = escape.json_decode(
        handler.get_secure_cookie(MIRACL_COOKIE_USERDATA_KEY))
    return data


def get_user_id(handler):
    data = _get_userdata(handler)
    return data["sub"]


def get_email(handler):
    data = _get_userdata(handler)
    if "email" not in data:
        return ""
    return data["email"]


@auth_return_future
def _oauth2_request(handler, url, callback, access_token=None,
                    post_args=None, **args):
    if access_token is None:
        access_token = handler.get_secure_cookie(MIRACL_COOKIE_TOKEN_KEY)
    all_args = {}
    all_args.update(args)
    if all_args:
        url += "?" + urllib_parse.urlencode(all_args)
    callback = functools.partial(_on_oauth2_request, callback)
    http = httpclient.AsyncHTTPClient()
    if post_args is not None:
        http.fetch(url, method="POST",
                   body=urllib_parse.urlencode(post_args),
                   callback=callback,
                   headers={"Authorization": "Bearer " + access_token}
                   )
    else:
        http.fetch(url,
                   callback=callback,
                   headers={"Authorization": "Bearer " + access_token}
                   )


def _on_oauth2_request(future, response):
    if response.error:
        future.set_result(None)
    future.set_result(escape.json_decode(response.body))
