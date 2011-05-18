from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash

from wire.models.user import User
from wire.models.message import Message, MessageError
from wire.models.inbox import Inbox
from wire.models.thread import Thread, DestroyedThreadError, ThreadError, InvalidRecipients
from wire.models.contacts import Contacts, ContactExistsError, ContactInvalidError
from wire.models.event import Event
from wire.utils.auth import Auth, AuthError, DeniedError
from wire.utils.crypto import DecryptFailed

from flaskext.markdown import Markdown
from flaskext.uploads import (UploadSet, configure_uploads, IMAGES,
                              UploadNotAllowed)

import json
import redis
import os, uuid, subprocess, shlex

# Default Configuration
DEBUG                   = True
SECRET_KEY              = 'TEST KEY'
UPLOADED_AVATARS_DEST   = 'wire/static/img/avatar'
REDIS_HOST              = 'localhost'
REDIS_PORT              = 6379
REDIS_DB                = 0

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('WIRE_SETTINGS', silent=True)
Markdown(app)

uploaded_avatars = UploadSet('avatars', IMAGES)

redis_connection = redis.Redis(
    host=app.config['REDIS_HOST'],
    port=app.config['REDIS_PORT'],
    db=app.config['REDIS_DB']
)

configure_uploads(app, uploaded_avatars)

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
                t.save()
                t.add_message(m)
                m.send()
                t.load(thread_id)
            try:
                encryption_key = request.form['encryption_key']
                t.decrypt(encryption_key)
                flash('Thread successfully decrypted.', 'success')
                decrypted = True
            except DecryptFailed:
                flash('Decryption was unsuccessful.', 'error')
                return redirect(url_for('view_thread', thread_id=thread_id))
            except DestroyedThreadError:
                flash('System error. Message lost.', 'error')
                return redirect(url_for('inbox'))
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

@app.route('/send/<string:recipient>')
def send_message_recipient(recipient):
    return send_message(recipient=recipient)

@app.route('/send', methods=['POST', 'GET'])
def send_message(recipient=False):
    try:
        g.user.username
    except AttributeError:
        abort(401)
    
    t = Thread(redis=g.r, user=g.user)
    m = Message(redis=g.r, key=False, user=g.user)
    if(recipient):
        try:
            t.parse_recipients(recipient)
        except InvalidRecipients:
            pass

    if request.method == 'POST':
        try:
            t.subject = request.form['subject']
            m.update(request.form)
            t.parse_recipients(request.form['recipients'])
            t.save()
            t.add_message(m)
            m.send()
            flash('Your message has been successfully wired, \
                    and should arrive shortly.', 'success')
            return redirect(url_for('view_thread', thread_id=t.key))
        except message.ValidationError:
            for error in m.validation_errors:
                flash(error, 'error')
        except InvalidRecipients:
            for recipient in t.invalid_recipients:
                flash('%s is not a valid recipient' % recipient, 'error')
    return render_template('forms/message.html',
        new=True,
        message=m,
        thread=t,
        recipients=t.get_form_recipients())

@app.route('/delete-message/<int:message_id>/<int:thread_id>', methods=['POST', 'GET'])
def delete_message(message_id, thread_id):
    if request.method == 'POST':
        t = Thread(redis=g.r, user=g.user)
        t.load(thread_id)
        m = Message(redis=g.r, user=g.user, key=message_id)
        m.load()
        if g.r.get('username:%s' % m.sender.username) != g.user.key:
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

@app.route('/unsubscribe-thread/<int:thread_id>', methods=['POST', 'GET'])
def unsubscribe_thread(thread_id):
    try:
        g.user.username
    except AttributeError:
        abort(401)
    if request.method == "POST":
        t = Thread(redis=g.r, user=g.user)
        t.load(thread_id)
        t.unsubscribe()
        flash(u'Unsubscribed from thread.', 'success')
        return redirect(url_for('inbox'))
    else:
        return render_template('confirm.html',
            _message='Are you sure you wish to unsubscribe from this thread?',
            _ok=url_for('unsubscribe_thread', thread_id=thread_id),
            _cancel=url_for('inbox')
        )

@app.route('/delete-thread/<int:thread_id>', methods=['POST', 'GET'])
def del_thread(thread_id):
    try:
        g.user.username
        if str(thread_id) not in g.user.get_threads():
            abort(401)
    except AttributeError:
        abort(401)
    if request.method == "POST":
        t = Thread(redis=g.r, user=g.user)
        t.load(thread_id)
        t.delete()
        flash(u'Deleted thread.', 'success')
        return redirect(url_for('inbox'))
    else:
        return render_template('confirm.html',
            _message='Are you sure you wish to DELETE this thread?',
            _ok=url_for('del_thread', thread_id=thread_id),
            _cancel=url_for('inbox')
        )

@app.route('/add-recipient/<int:thread_id>', methods=['POST', 'GET'])
def add_recipient(thread_id):
    try:
        g.user.username
        if str(thread_id) not in g.user.get_threads():
            abort(401)
    except AttributeError:
        abort(401)
    username = request.form['username']
    if request.form['confirm'] == '1':
        try:
            t = Thread(redis=g.r, user=g.user)
            t.load(thread_id)
            t.parse_recipients(username)
            t.save()
            flash('Added recipient.', 'success')
        except InvalidRecipients:
            flash(u'Invalid recipient.', 'error')
        return redirect(url_for('view_thread', thread_id=thread_id))
    else:
        return render_template('confirm.html',
            _message='Are you sure you wish to add recipient %s to this thread?' % username,
            _ok=url_for('add_recipient', thread_id=thread_id),
            _cancel=url_for('view_thread', thread_id=thread_id),
            _hiddens=[('username', username)]
        )
        
@app.route('/address-book')
def contacts(async=False):
    try:
        g.user.username
    except AttributeError:
        abort(401)
    c = Contacts(redis=g.r, user=g.user)
    if async:
        return json.dumps(c.contacts)
    else:
        return render_template('contacts.html',
            contacts=c.contacts
        )
@app.route('/async/address-book')
def async_contacts():
    return contacts(async=True)

@app.route('/add-contact/<string:contact>')
def add_contact(contact):
    try:
        g.user.username
    except AttributeError:
        abort(401)
    try:
        c = Contacts(redis=g.r, user=g.user)
        c.add(contact)
        flash('Added user "%s" to address book.' % contact, 'success')
    except KeyError:
        flash('No user specified.', 'error')
    except ContactInvalidError:
        flash('User "%s" does not exist.' % contact, 'error')
    except ContactExistsError:
        flash('User "%s" is already in your address book.' % contact, 'error')
    return redirect(url_for('contacts'))

@app.route('/add-contact', methods=['POST'])
def add_contact_post():
    contact = request.form['username']
    return add_contact(contact)

@app.route('/async/contact/search/<string:part>')
def async_contact_search(part):
    try:
        g.user.username
    except AttributeError:
        abort(401)
    c = Contacts(redis=g.r, user=g.user)
    return json.dumps(c.search(part))

@app.route('/delete-contact/<string:contact>')
def del_contact(contact):
    try:
        g.user.username
    except AttributeError:
        abort(401)
    c = Contacts(redis=g.r, user=g.user)
    c.delete(contact)
    flash('Deleted contact "%s".' % contact, 'success')
    return redirect(url_for('contacts'))

@app.route('/events')
def list_events():
    return render_template('events.html')

@app.route('/event/<int:event_id>')
def view_event(event_id):
    return "viewing event", event_id

@app.route('/create-event')
def new_event():
    e = Event(redis=g.r, user=g.user)
    return render_template('forms/event.html',
        event=e
    )

@app.route('/save-event')
def save_event():
    pass

@app.route('/blog')
def blog_entries():
    return render_template('blog.html')

@app.route('/blog/<int:entry_id>')
def view_blog_entry(entry_id):
    return "viewing entry",  entry_id

@app.route('/sign-up', methods=['POST', 'GET'])
def new_user():
    return edit_user(new=True)

@app.route('/edit-profile', methods=['POST', 'GET'])
def edit_user(new=False):
    if not new:
        try:
            g.user.username
        except AttributeError:
            abort(401)
    
    if new:
        u = user.User(redis=g.r)
    else:
        u = g.user
    if request.method == 'POST':
        u.update(request.form, new=new)
        
        try:
            avatar = request.files.get('avatar')
            if avatar:
                try:
                    u.avatar = upload_avatar(avatar)
                    flash("Upload successful.", 'success')
                except UploadNotAllowed:
                    flash("Upload not allowed.", 'error')
            u.save()
            if new:
                flash('"User "%s" created successfully. \
                    You may now log in.' % u.username, 'success')
                return redirect(url_for('intro'))
            else:
                flash('Profile updated.', 'success')
                print u.data
                return redirect(url_for('edit_user'))
        except user.ValidationError:
            for error in u.validation_errors:
                flash(error, 'error')
    
    return render_template('forms/user.html',
        new=new,
        user=u
    )

def upload_avatar(avatar):
    ext = avatar.filename.split(".")[-1]
    filename = uploaded_avatars.save(avatar, name="%s.%s" % (unique_id(), ext))
    path = "%s/%s" % (UPLOADED_AVATARS_DEST, filename)
    args = [
        'convert',
        path,
        '-resize',
        '80x80^',
        '-gravity',
        'center',
        '-extent',
        '80x80',
        path
    ]
    p = subprocess.Popen(args)
    return filename

def unique_id():
    return hex(uuid.uuid4().time)[2:-1]

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
    try:
        session.pop('logged_in')
        flash('Logged out.', 'success')
    except KeyError:
        pass
    return redirect(url_for('intro'))   

if __name__ == '__main__':
    app.run()

