import miracl_api_tornado as auth
from tornado import web, ioloop


class AuthHandler(auth.MiraclAuthRequestHandler):
    def on_auth_success(self, user_data):
        self.set_secure_cookie("e-mail", user_data['sub'])
        self.redirect("/")

    def on_auth_failed(self):
        self.write("Auth failed. <a href=\"/c2id?login\">Retry?</a>")


class MainHandler(web.RequestHandler):
    def get(self):
        if auth.is_authenticated(self):
            self.write(
                "<h1>Hello, {0}</h1><a href=\"/logout\">Logout</a>".format(
                    self.get_secure_cookie("e-mail")))
        else:
            self.write("<h1>Hello!</h1><a href=\"/c2id?login\">Login</a>")


class LogoutHandler(web.RequestHandler):
    def get(self):
        auth.logout(self)
        self.redirect("/")


if __name__ == "__main__":
    settings = {
        'cookie_secret': 'secret',
        'xsrf_cookies': True,
        'debug': True,
        'miracl': {
            'client_id': 'CLIENT_ID',
            'secret': 'CLIENT_SECRET',
            'redirect_uri': 'REDIRECT_URL',
        }
    }
    app = web.Application([
        (r"/", MainHandler),
        (r"/c2id", AuthHandler),
        (r"/logout", LogoutHandler)
    ],
        **settings
    )

    app.listen(8888)
    ioloop.IOLoop.current().start()
