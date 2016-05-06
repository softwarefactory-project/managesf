from pecan import request, abort, conf

from functools import wraps


def user_login_required(func):
    '''Requires a user logged in.
    '''
    @wraps(func)
    def dec_func(*args, **kwargs):
        if request.remote_user is None:
            abort(401)
        return func(*args, **kwargs)

    return dec_func


def admin_login_required(func):
    @wraps(func)
    def dec_func(*args, **kwargs):
        if request.remote_user is None:
            abort(401)
        if conf.admin['name'] != request.remote_user:
            abort(403)
        return func(*args, **kwargs)

    return dec_func
