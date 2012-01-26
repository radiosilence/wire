from flask import Flask

from flaskext.markdown import Markdown
from flaskext.uploads import (UploadSet, configure_uploads, IMAGES,
                              UploadNotAllowed)

import logging
from logging import Formatter, FileHandler

from settings import *

uploaded_avatars = UploadSet('avatars', IMAGES)
uploaded_images = UploadSet('images', IMAGES)

def create_app(debug=False):
    if debug:
        print "Debug mode."
        app = Flask(__name__)

    else:
        app = Flask(__name__, static_path='/')

    app.config.from_object(__name__)
    app.config.from_envvar('WIRE_SETTINGS', silent=True)
    app.config['DEBUG'] = debug
    configure_uploads(app, uploaded_avatars)
    configure_uploads(app, uploaded_images)
    Markdown(app)


    if not debug:
        file_handler = FileHandler('error.log', encoding="UTF-8")
        file_handler.setLevel(logging.WARNING)
        file_handler.setFormatter(Formatter(
            '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(funcName)s:%(lineno)d]'
        ))
        app.logger.addHandler(file_handler)

    return app

app = create_app(debug=DEBUG)

import wire.views