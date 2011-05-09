from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash

import user, message
from utils.auth import Auth, AuthError

import redis

class _DefaultSettings(object):
    SECRET_KEY = 'default key'
    DEBUG = True


app = Flask(__name__)

app.config.from_object(_DefaultSettings)
del _DefaultSettings

@app.before_request
def before_request():
    g.r = redis.Redis(host='localhost', port=6379, db=0)
    g.auth = Auth(g.r)
    g.user = user.User(redis=g.r)
    try:
        if session['logged_in']:
            g.user.load(session['logged_in'])
    except KeyError:
        pass

@app.after_request
def after_request(response):
    """Closes the database again at the end of the request."""
    session.pop('user', g.auth.user)
    return response

@app.route('/')
def intro():
    return render_template('intro.html')

@app.route('/sign-up', methods=['POST', 'GET'])
def new_user():
    return edit_user(new=True)

@app.route('/edit-profile', methods=['POST', 'GET'])
def edit_user(new=False):
    errors = []
    
    if new:
        u = user.User(redis=g.r, key=False)
    else:
        u = g.user

    u.update(request.form, new=new)

    if request.method == 'POST':
        try:
            u.save()
            if new:
                return render_template('message.html',
                    status="User Created",
                    message="""User %s created successfully.
                        You may now log in.""" % u.username
                )
        except user.ValidationError:
            errors = u.validation_errors

    return render_template('forms/user.html',
        new=new,
        user=u,
        errors=errors
    )


@app.route('/send')
def send_message():
    return render_template('forms/message.html')

@app.route('/inbox')
def inbox():
    return "Inbox"

@app.route('/message/<int:message_id>')
def view_message(message_id):
    return "View Message", message_id

@app.route('/events')
def list_events():
    return "events list"

@app.route('/event/<int:event_id>')
def view_event(event_id):
    return "viewing event", event_id

@app.route('/blog')
def blog_entries():
    return "blog entries"

@app.route('/blog/<int:entry_id>')
def view_blog_entry(entry_id):
    return "viewing entry",  entry_id

@app.route('/login', methods=['POST'])
def login():
    try:
        g.auth.attempt(request.form['username'], request.form['password'])
        session['logged_in'] = g.auth.user.key
        g.user.load(g.auth.user.key)
    except (KeyError, AuthError):
        return render_template('message.html',
            status='Fail',
            message='Incorrect username or password.')
    return render_template('message.html',
        status='Success',
        message='Logged in as %s.' % request.form['username'])

@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.pop('logged_in')
    return render_template('message.html',
        status='Logged out',
        message='Goodbye, %s.' % g.user.username)

if __name__ == '__main__':
    app.run()

