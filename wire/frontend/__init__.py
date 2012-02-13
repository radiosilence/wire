from flask import Blueprint, g, session, config, current_app

from wire.models import User, Inbox, UserNotFoundError
from wire.utils import Auth

import redis

frontend = Blueprint('frontend', __name__,
    template_folder='templates')


@frontend.before_request
def before_request():
    g.logged_in = False
    g.r = redis.Redis(
        host=current_app.config['REDIS_HOST'],
        port=current_app.config['REDIS_PORT'],
        db=current_app.config['REDIS_DB']
    )

    g.auth = Auth(g.r)
    g.user = User(redis=g.r)
    g.GMAPS_KEY = current_app.config['GMAPS_KEY']
    try:
        if session['logged_in']:
            g.logged_in = True
            g.user.load(session['logged_in'])
            g.inbox = Inbox(user=g.user, redis=g.r)
            g.unread_count = g.inbox.unread_count()
    except KeyError:
        pass
    except UserNotFoundError:
        from views import logout
        logout()


@frontend.after_request
def after_request(response):
    """Closes the database again at the end of the request."""
    session.pop('user', g.auth.user)
    return response

import views
