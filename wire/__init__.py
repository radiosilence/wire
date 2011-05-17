from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash

from wire.user import User
from wire.message import Message, MessageError
from wire.inbox import Inbox
from wire.thread import Thread, DestroyedThreadError, ThreadError, InvalidRecipients
from wire.utils.auth import Auth, AuthError, DeniedError
from wire.utils.crypto import DecryptFailed

import redis
import os
# configuration
DEBUG = True
SECRET_KEY = 'DEV KEYMO'

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('FLASKR_SETTINGS', silent=True)
redis_connection = redis.Redis(host="localhost", port=6379, db=0)
@app.before_request
def before_request():
    g.r = redis_connection
    g.auth = Auth(g.r)
    g.user = User(redis=g.r)

    try:
        if session['logged_in']:
            g.user.load(session['logged_in'])
            g.inbox = Inbox(user=g.user, redis=g.r)
            g.unread_count = g.inbox.unread_count()
    
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

@app.route('/developers')
def developers():
    return render_template('developers.html')

@app.route('/inbox')
def inbox():
    i = g.inbox
    i.load_messages()
    if len(i.threads) == 0:
        empty = True
    else:
        empty = False
    return render_template('inbox.html',
        threads=i.threads,
        empty=empty)

@app.route('/thread/<int:thread_id>', methods=['POST', 'GET'])
def view_thread(thread_id):
    encryption_key = False
    decrypted = False
    if str(thread_id) not in g.user.get_threads():
        abort(401)

    t = Thread(redis=g.r, user=g.user)
    try:
        t.load(thread_id)
        if request.method == "POST":
            if request.form['action'] == 'reply':
                m = Message(redis=g.r, key=False, user=g.user)
                m.update(request.form)
                m.send()
                t.save()
                t.add_message(m)
                t.load(thread_id)
            try:
                encryption_key = request.form['encryption_key']
                t.decrypt(encryption_key)
                flash('Thread successfully decrypted.', 'success')
                decrypted = True
            except (DecryptFailed, DestroyedThreadError):
                flash('Decryption was unsuccessful.', 'error')
                return redirect(url_for('view_thread', thread_id=thread_id))
            except KeyError:
                pass
        
        if t.decrypted:
            t.reset_unread_count()

        return render_template('thread.html',
            messages=t.messages,
            thread=t,
            decrypted=t.decrypted,
            encryption_key=encryption_key,
            subject=t.subject)
    except ThreadError:
         abort(404)

@app.route('/send', methods=['POST', 'GET'])
def send_message():
    try:
        g.user.username
    except AttributeError:
        abort(401)
    
    t = Thread(redis=g.r, user=g.user)
    m = Message(redis=g.r, key=False, user=g.user)
    if request.method == 'POST':
        try:
            t.subject = request.form['subject']
            m.update(request.form)
            t.parse_recipients(request.form['recipients'])
            m.send()
            t.save()
            t.add_message(m)
            flash('Your message has been successfully wired, \
                    and should arrive shortly.', 'success')
            return redirect(url_for('view_thread', thread_id=t.key))
        except message.ValidationError:
            for error in m.validation_errors:
                flash(error, 'error')
        except InvalidRecipients:
            print "Invalid recipients", t.invalid_recipients
            for recipient in t.invalid_recipients:
                flash('%s is not a valid recipient' % recipient, 'error')
    return render_template('forms/message.html',
        new=True,
        message=m,
        thread=t)

@app.route('/delete-message/<int:message_id>/<int:thread_id>', methods=['POST', 'GET'])
def delete_message(message_id, thread_id):
    if request.method == 'POST':
        t = Thread(redis=g.r, user=g.user)
        t.load(thread_id)
        m = Message(redis=g.r, user=g.user, key=message_id)
        m.load()
        if g.r.get('username:%s' % m.sender) != g.user.key:
            abort(401)
        t.delete_message(m)
        flash(u'Message deleted', 'success')
        return redirect(url_for('view_thread', thread_id=thread_id))
    else:
        return render_template('confirm.html',
            _message='Are you sure you want to delete this message?',
            _ok=url_for('delete_message', thread_id=thread_id, message_id=message_id),
            _cancel=url_for('view_thread', thread_id=thread_id)
        )

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

@app.route('/sign-up', methods=['POST', 'GET'])
def new_user():
    return edit_user(new=True)

@app.route('/edit-profile', methods=['POST', 'GET'])
def edit_user(new=False):
    try:
        g.user.username
    except AttributeError:
        abort(401)
    
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
            for error in u.validation_errors:
                flash(error, 'error')

    return render_template('forms/user.html',
        new=new,
        user=u
    )


@app.route('/login', methods=['POST'])
def login():
    try:
        g.auth.attempt(request.form['username'], request.form['password'])
        session['logged_in'] = g.auth.user.key
        g.user.load(g.auth.user.key)
    except (KeyError, AuthError):
        flash('Incorrect username or password.', 'error')
        return redirect(url_for('intro'))
    flash('Successfully logged in.', 'success')
    return redirect(url_for('inbox'))

@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.pop('logged_in')
    try:
        return render_template('status.html',
            _status='Logged out',
            _message='Goodbye, %s.' % g.user.username)
    except AttributeError:
        return "Logged out."

if __name__ == '__main__':
    app.run()

