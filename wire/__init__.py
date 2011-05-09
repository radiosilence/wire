from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash

from wire.user import User
from wire.message import Message, MessageError
from wire.inbox import Inbox
from wire.utils.auth import Auth, AuthError
from wire.utils.crypto import DecryptFailed

import redis
import os
# configuration
DEBUG = True
SECRET_KEY = 'DEV KEYMO'

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

@app.before_request
def before_request():
    g.r = redis.Redis(host='localhost', port=6379, db=0)
    g.auth = Auth(g.r)
    g.user = User(redis=g.r)
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
                return render_template('status.html',
                    _status="User Created",
                    _message="""User %s created successfully.
                        You may now log in.""" % u.username
                )
        except user.ValidationError:
            errors = u.validation_errors

    return render_template('forms/user.html',
        new=new,
        user=u,
        _errors=errors
    )

@app.route('/send', methods=['POST', 'GET'])
def send_message():
    errors = []
    m = message.Message(redis=g.r, key=False, user=g.user)
    if request.method == 'POST':
        m.update(request.form)
        try:
            m.send()
            return render_template('status.html',
                _status='Message Wired',
                _message='Your message has been successfully wired, \
                    and should arrive shortly.')
        except message.ValidationError:
            errors = m.validation_errors
        except message.InvalidRecipients:
            errors = ['%s is not a valid recipient.' % r for r in m.invalid_recipients]
    
    return render_template('forms/message.html',
        new=True,
        message=m,
        _errors=errors)

@app.route('/inbox')
def inbox():
    i = Inbox(user=g.user, redis=g.r)
    i.load()
    if len(i.messages) == 0:
        empty = True
    else:
        empty = False
    return render_template('inbox.html',
        messages=i.messages,
        empty=empty)

@app.route('/message/<int:message_id>', methods=['POST', 'GET'])
def view_message(message_id):
    m = Message(redis=g.r, user=g.user)
    encryption_key = False
    try:
        m.load(message_id)
        if request.method == 'POST':
            if request.form['action'] == 'reply':
                print "Reply."
            if request.form['action'] == 'decrypt':
                encryption_key = request.form['encryption_key']
                try:
                    m.decrypt(encryption_key)
                except DecryptFailed:
                    return render_template('status.html',
                        _status='Fail',
                        _message='Decryption was unsucessful.')
        return render_template('message.html',
            message=m,
            encryption_key=encryption_key)
    except MessageError:
        return render_template('status.html', 
            _status='404',
            _message='Message not found.')

@app.route('/events')
def list_events():
    return "events list"

@app.route('/event/<int:event_id>')
def view_event(event_id):
    return "viewing event", event_id

@app.route('/create-event')
def new_event():
    return "creatin event"

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
        return render_template('status.html',
            _status='Fail',
            _message='Incorrect username or password.')
    return render_template('status.html',
        _status='Success',
        _message='Logged in as %s.' % request.form['username'])

@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.pop('logged_in')
    return render_template('status.html',
        _status='Logged out',
        _message='Goodbye, %s.' % g.user.username)

if __name__ == '__main__':
    app.run()

