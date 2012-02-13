import sys
import logging
from logging import Formatter, FileHandler

from flask import Flask, render_template

from flaskext.markdown import Markdown
from flaskext.uploads import configure_uploads, UploadSet, IMAGES

from wire.settings import *

uploaded_avatars = UploadSet('avatars', IMAGES)
uploaded_images = UploadSet('images', IMAGES)

def create_app(debug=False):
    if debug:
        print "Debug mode."
        app = Flask('wire', static_path='/static/')

    else:
        app = Flask('wire', static_path='/')

    app.config.from_object('wire.settings')
    app.config.from_envvar('WIRE_SETTINGS', silent=True)
    app.config['DEBUG'] = debug
    configure_uploads(app, uploaded_avatars)
    configure_uploads(app, uploaded_images)
    Markdown(app)

    if not debug:
        configure_logging(app)

    from wire.frontend import frontend
    app.register_blueprint(frontend, url_prefix='')

    configure_base_views(app)

    if app.config['SECRET_KEY'] == '':
        print 'Please setup a secret key in local_settings.py!!!'

    return app

def configure_logging(app):
    file_handler = FileHandler(app.config['LOG_LOCATION'],
        encoding="UTF-8")
    file_handler.setLevel(logging.WARNING)
    file_handler.setFormatter(Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(funcName)s:%(lineno)d]'
    ))
    app.logger.addHandler(file_handler)

def configure_base_views(app):
    
    @app.errorhandler(401)
    def unauthorized(error):
        return _status(error), 401

    @app.errorhandler(404)
    def not_found(error):
        return _status(error), 404

    @app.errorhandler(500)
    def fuckup(error):
        return _status("500: Internal Server Error"), 500

def _status(error):
    status = [x.strip() for x in str(error).split(":")]
    return render_template('status.html',
        _status=status[0],
        _message=status[1]
        )
