from __future__ import unicode_literals
from builtins import str
import functools

from tornado.auth import AuthError
from tornado.concurrent import TracebackFuture
from tornado.log import gen_log
from tornado.stack_context import ExceptionStackContext
from tornado.util import ArgReplacer


def auth_future_to_callback(callback, future):
    try:
        result = future.result()
    except AuthError as e:
        gen_log.warning(str(e))
        result = None
    callback(result)


def auth_return_future(f):
    replacer = ArgReplacer(f, 'callback')

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        future = TracebackFuture()
        callback, args, kwargs = replacer.replace(future, args, kwargs)
        if callback is not None:
            future.add_done_callback(
                functools.partial(auth_future_to_callback, callback))

        def handle_exception(typ, value, tb):
            if future.done():
                return False
            else:
                future.set_exc_info((typ, value, tb))
                return True
        with ExceptionStackContext(handle_exception):
            f(*args, **kwargs)
        return future
    return wrapper
