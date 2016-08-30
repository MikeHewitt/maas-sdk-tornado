from __future__ import unicode_literals
import miracl_api_tornado as auth
from tornado import web, ioloop, gen
import json


def read_configuration():
    """
    :return: Dictionary representing configuration file
    """
    config_file = open("miracl.json")
    config = json.load(config_file)
    config_file.close()
    return config


def flash_message(handler, category, message):
    """
    Save message for user in secure cookie
    :param handler: Handler for access to cookies
    :param category: Category of message. Default Bootstrap categories are:
        success, info, warning, danger
    :param message: Message text
    """
    # Get messages string from cokie
    messages_json = handler.get_secure_cookie("messages")
    if not messages_json:
        # If messages was not set, create empty list
        messages = []
    else:
        # If messages was set, decode messages
        messages = json.loads(messages_json)
    # Add new message to list
    messages.append({"category": category, "message": message})
    # Serialize and put modified list into cookie
    handler.set_secure_cookie("messages", json.dumps(messages))


def render_template(handler, **kwargs):
    """
    Render template. This method will start output to client. No modifications
    of headers (including cookies) will work after call to this method for
    current request.
    :param handler: Handler for access to cookies
    :param kwargs: Model - template arguments
    """
    # Read messages from cookie
    messages_json = handler.get_secure_cookie("messages")
    if not messages_json:
        messages = []
    else:
        messages = json.loads(messages_json)

    # Set messages cooke to empty list
    handler.set_secure_cookie("messages", "[]")

    # Set potentially missing flags for template model (defaulting to False)
    if "retry" not in kwargs:
        kwargs["retry"] = False
    if "is_authorized" not in kwargs:
        kwargs["is_authorized"] = False

    # Render template
    handler.render("index.html", messages=messages, **kwargs)


class AuthHandler(auth.MiraclAuthRequestHandler):
    """
    Callback route handler - called after user interaction with login button.
    It extends MiraclAuthRequestHandler that provides two abstract methods for
    reporting auth status. All auth processing is done in M
    iraclAuthRequestHandler.
    """

    def on_auth_success(self, user_data):
        # Notify user about success
        flash_message(self, "success", "Successfully logged in!")
        # Redirect to default route
        self.redirect("/")

    def on_auth_failed(self):
        # Notify user about failure
        flash_message(self, "danger", "Login failed!")
        # Render retry template
        render_template(self, retry=True, auth_url=auth.get_login_url(self))


class MainHandler(web.RequestHandler):
    """
    Default route handler - Displays user information for logged in user and
    login button for user not yet logged in
    """

    def get(self):
        if auth.is_authenticated(self):
            # If authenticated, render template with user data
            email = auth.get_email(self)
            user_id = auth.get_user_id(self)
            render_template(self, is_authorized=True,
                            email=email,
                            user_id=user_id)
        else:
            # If not authenticated, render template with login button
            render_template(self, auth_url=auth.get_login_url(self))


class LogoutHandler(web.RequestHandler):
    """
    Log out route handler - clears user data and auth info, notifies user about
    logout and redirects back to default route
    """

    def get(self):
        auth.logout(self)
        flash_message(self, "info", "User logged out!")
        self.redirect("/")


class RefreshHandler(web.RequestHandler):
    """
    Refresh route handler - Refreshes user data and redirects back to default
    route. Can clear authentication if access token is expired
    """
    @gen.coroutine
    def get(self):
        # User data executes http request - we need to yield
        yield auth.refresh_user_data(self)
        self.redirect("/")

# If this is startup file
if __name__ == "__main__":
    # Set up Tornado parameters including Miracl client parameters
    settings = {
        'cookie_secret': 'secret',
        'xsrf_cookies': True,
        'debug': True,
        'miracl': read_configuration()
    }
    # Create web application with defined route handlers and previously created
    # settings
    app = web.Application([
        (r"/", MainHandler),
        (r"/c2id", AuthHandler),
        (r"/logout", LogoutHandler),
        (r"/refresh", RefreshHandler)
    ],
        **settings
    )

    # Set listening port
    app.listen(5000)
    # Start IOLoop
    ioloop.IOLoop.current().start()
