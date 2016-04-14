from __future__ import absolute_import, division, print_function, \
    with_statement
import os
from abc import ABCMeta, abstractmethod

import functools

import tornado
import tornado.web
from tornado import escape
from tornado import gen
from tornado.auth import OAuth2Mixin, _auth_return_future, AuthError
import base64


try:
    import urllib.parse as urllib_parse  # py3
except ImportError:
    import urllib as urllib_parse  # py2

MIRACL_COOKIE_TOKEN_KEY = 'miracl_token'


class MiraclMixin(tornado.web.RequestHandler, OAuth2Mixin):
    __metaclass__ = ABCMeta
    _OAUTH_AUTHORIZE_URL = 'https://m-pin.my.id/abstractlogin'
    _OAUTH_ACCESS_TOKEN_URL = 'https://m-pin.my.id/c2id/token'
    _OAUTH_USERINFO_URL = 'https://m-pin.my.id/c2id/userinfo'
    _OAUTH_SETTINGS_KEY = 'miracl'

    @tornado.gen.coroutine
    def get(self):
        if self.get_argument('code', False):
            state = self.get_secure_cookie('miracl_state')
            current_state = self.get_argument('state')
            if current_state and state != current_state:
                self.on_auth_failed()
                return
            access = yield self.get_authenticated_user(
                redirect_uri=self.settings[self._OAUTH_SETTINGS_KEY][
                    'redirect_uri'],
                code=self.get_argument('code'))
            self.set_secure_cookie(MIRACL_COOKIE_TOKEN_KEY,
                                   access['access_token'])
            data = yield self.oauth2_request(
                self._OAUTH_USERINFO_URL,
                access_token=access['access_token'])
            self.on_auth_success(data)
        else:
            try:
                self.get_argument('login')
                state = self._gen_state()
                self.set_secure_cookie('miracl_state', state)
                yield self.authorize_redirect(
                    redirect_uri=self.settings[self._OAUTH_SETTINGS_KEY][
                        'redirect_uri'],
                    client_id=self.settings[self._OAUTH_SETTINGS_KEY][
                        'client_id'],
                    scope=['openid', 'profile', 'email'],
                    response_type='code',
                    extra_params={'approval_prompt': 'auto', 'state': state})
            except tornado.web.MissingArgumentError:
                logout(self)
                self.on_auth_failed()

    @_auth_return_future
    def get_authenticated_user(self, redirect_uri, code, callback):
        http = self.get_auth_http_client()
        body = urllib_parse.urlencode({
            'redirect_uri': redirect_uri,
            'code': code,
            'client_id': self.settings[self._OAUTH_SETTINGS_KEY]['client_id'],
            'client_secret': self.settings[self._OAUTH_SETTINGS_KEY]['secret'],
            'grant_type': 'authorization_code',
        })

        http.fetch(self._OAUTH_ACCESS_TOKEN_URL,
                   functools.partial(self._on_access_token, callback),
                   method='POST',
                   headers={
                       'Content-Type': 'application/x-www-form-urlencoded'},
                   body=body)

    def get_user_details(self):
        token = self.get_secure_cookie(MIRACL_COOKIE_TOKEN_KEY)

    def _on_access_token(self, future, response):
        if response.error:
            future.set_exception(
                AuthError('Miracl auth error: %s' % str(response)))
            return
        args = escape.json_decode(response.body)
        future.set_result(args)

    @staticmethod
    def _gen_state():
        """ Generates a random string of bytes, base64 encoded """
        length = 12
        string = base64.b64encode(os.urandom(length), altchars=b'-_')
        b64len = 4 * length // 3
        if length % 3 == 1:
            b64len += 2
        elif length % 3 == 2:
            b64len += 3
        return string[0:b64len].decode()

    @abstractmethod
    def on_auth_success(self, user_data):
        pass

    @abstractmethod
    def on_auth_failed(self):
        pass


def is_authenticated(handler):
    token = handler.get_secure_cookie(MIRACL_COOKIE_TOKEN_KEY)
    return token is not None


def logout(handler):
    handler.clear_cookie(MIRACL_COOKIE_TOKEN_KEY)
