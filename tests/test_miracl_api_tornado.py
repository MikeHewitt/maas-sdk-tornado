from __future__ import unicode_literals
from future import standard_library
standard_library.install_aliases()
from builtins import object
import http.cookies
import json
import unittest

import miracl_api_tornado
from mock import patch

from tornado import web, gen, escape
from tornado.concurrent import TracebackFuture
from tornado.httpclient import HTTPRequest, HTTPResponse
from tornado.web import Application
from tornado.testing import AsyncHTTPTestCase, AsyncTestCase

from tornado_stub_client import stub, RequestCollection


class AsyncHTTPStubClient(object):

    def fetch(self, request, callback=None, **kwargs):
        if not isinstance(request, HTTPRequest):
            request = HTTPRequest(url=request, **kwargs)
        response_partial = RequestCollection.find(request)
        if response_partial:
            resp = response_partial(request)
        else:
            resp = HTTPResponse(request, 404)
        if callback is not None:
            callback(resp)
        else:
            future = TracebackFuture()
            future.set_result(resp)
            return future


class AuthHandler(miracl_api_tornado.MiraclAuthRequestHandler):

    def on_auth_success(self, user_data):
        self.write("success")

    def on_auth_failed(self):
        self.write("fail")


class MainHandler(web.RequestHandler):

    def get(self):
        if miracl_api_tornado.is_authenticated(self):
            email = miracl_api_tornado.get_email(self)
            user_id = miracl_api_tornado.get_user_id(self)
            self.write("authenticated," + user_id + "," + email)
        else:
            self.write("login," + miracl_api_tornado.get_login_url(self))


class LogoutHandler(web.RequestHandler):

    def get(self):
        miracl_api_tornado.logout(self)
        self.write("logout")


class RefreshHandler(web.RequestHandler):

    @gen.coroutine
    def get(self):
        yield miracl_api_tornado.refresh_user_data(self)
        self.write("refresh")


def url_to_dict(url):
    if "?" in url:
        url = url.split("?")[1]
    parts = url.split("&")
    d = {}
    for p in parts:
        kv = p.split("=")
        k = kv[0]
        if len(kv) > 1:
            v = kv[1]
        else:
            v = ""
        d[k] = v

    return d


settings = {
    'cookie_secret': 'secret',
    'debug': True,
    'miracl': {
        'client_id': 'MOCK_CLIENT',
        'secret': 'MOCK_SECRET',
        'redirect_uri': 'http://mock.redirect.url',
    }
}


def get_app():
    app = Application([
        (r"/", MainHandler),
        (r"/c2id", AuthHandler),
        (r"/logout", LogoutHandler),
        (r"/refresh", RefreshHandler)
    ], **settings)
    return app


class MockHandler(object):

    def __init__(self):
        self.cookies = {}
        self.settings = settings

    def set_secure_cookie(self, k, v):
        self.cookies[k] = v

    def get_secure_cookie(self, k):
        try:
            return self.cookies[k]
        except KeyError:
            return None

    def clear(self):
        self.cookies = {}


def get_mock_http(ignored=None):
    return AsyncHTTPStubClient()


class TestBasics(AsyncTestCase):

    @classmethod
    def setUpClass(cls):
        cls.mock_handler = MockHandler()
        pass

    def test_auth_request_url(self):
        self.mock_handler.clear()
        url = miracl_api_tornado.get_login_url(self.mock_handler)
        self.assertIsNotNone(url)

        state_cookie = self.mock_handler.get_secure_cookie("miracl_state")
        self.assertTrue(
            state_cookie is not None,
            "Auth URL generation should set state cookie")

        self.assertTrue(
            ("state=" + state_cookie) in url
        )

    def test_auth_state_empty(self):
        self.mock_handler.clear()
        self.assertFalse(
            miracl_api_tornado.is_authenticated(self.mock_handler),
        )


class TestAuthFlow(AsyncHTTPTestCase):

    @classmethod
    def setUpClass(cls):
        cls.cookies = http.cookies.SimpleCookie()

    def _clear_cookies(self):
        self.cookies = http.cookies.SimpleCookie()

    def _update_cookies(self, headers):
        """
        from
        https://github.com/peterbe/tornado-utils/blob/master/tornado_utils/http_test_client.py
        """
        try:
            sc = headers.get_list('Set-Cookie')
            self.cookies = http.cookies.SimpleCookie()
            for c in sc:
                self.cookies.load(escape.native_str(c))

        except KeyError:
            return

    def fetch(self, path, **kwargs):
        if 'follow_redirects' not in kwargs:
            kwargs['follow_redirects'] = False
        header = {}
        hs = self.cookies.output(sep=',')
        if hs != "":
            hs = hs.split(':', 1)[1]
            header['Cookie'] = hs
        result = super(TestAuthFlow, self).fetch(path, headers=header,
                                                 **kwargs)
        self._update_cookies(result.headers)
        return result

    def get_app(self):
        self.app = get_app()
        return self.app

    def test_auth_callback(self):
        self._clear_cookies()  # clear session
        main = self.fetch("/")
        split = main.body.decode().split(",", 1)
        self.assertEqual("login", split[0],
                         "After logout state should be login")
        params = url_to_dict(split[1])

        state = params["state"]
        code = "CODECODE"
        http_patch = patch("tornado.httpclient.AsyncHTTPClient",
                           new=get_mock_http)
        http_patch.start()
        with stub(
                miracl_api_tornado.OAUTH_ACCESS_TOKEN_URL,
                method="POST").and_return(code=200,
                                          body_json={"access_token": "TOKEN"}):
            with stub(
                    miracl_api_tornado.OAUTH_USERINFO_URL,
                    method="GET").and_return(code=200,
                                             body_json={"sub": "MOCK",
                                                        "email": "MOCK@MOCK"}):
                auth_data = self.fetch(
                    "/c2id?state=" + state + "&code=" + code).body

                self.assertEqual(b"success", auth_data, "Login success")
        http_patch.stop()

        user_data = self.fetch("/")
        user_data = user_data.body.decode().split(",")
        self.assertEqual("authenticated", user_data[0])
        self.assertEqual("MOCK", user_data[1])
        self.assertEqual("MOCK@MOCK", user_data[2])
