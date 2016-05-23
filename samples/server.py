import miracl_api_tornado as auth
from tornado import web, ioloop
import json


def flash_message(handler, category, message):
    messages_json = handler.get_secure_cookie("messages")
    if not messages_json:
        messages = []
    else:
        messages = json.loads(messages_json)
    messages.append({"category": category, "message": message})
    handler.set_secure_cookie("messages", json.dumps(messages))


def render_template(handler, **kwargs):
    messages_json = handler.get_secure_cookie("messages")
    if not messages_json:
        messages = []
    else:
        messages = json.loads(messages_json)
    handler.set_secure_cookie("messages", "[]")

    if "retry" not in kwargs:
        kwargs["retry"] = False
    if "is_authorized" not in kwargs:
        kwargs["is_authorized"] = False

    handler.render("index.html", messages=messages, **kwargs)


class AuthHandler(auth.MiraclAuthRequestHandler):
    def on_auth_success(self, user_data):
        self.set_secure_cookie("sub", user_data['sub'])
        self.set_secure_cookie("email", user_data['email'])
        flash_message(self, "success", "Successfully logged in!")
        self.redirect("/")

    def on_auth_failed(self):
        flash_message(self, "danger", "Login failed!")
        render_template(self, retry=True, auth_url=auth.get_login_url(self))


class MainHandler(web.RequestHandler):
    def get(self):
        if auth.is_authenticated(self):
            render_template(self, is_authorized=True,
                            email=self.get_secure_cookie("email"),
                            user_id=self.get_secure_cookie("sub"))
        else:
            render_template(self, auth_url=auth.get_login_url(self))


class LogoutHandler(web.RequestHandler):
    def get(self):
        auth.logout(self)
        flash_message(self, "info", "User logged out")
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

    app.listen(5000)
    ioloop.IOLoop.current().start()
