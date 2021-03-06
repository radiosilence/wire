# Default Configuration
DEBUG = False
SECRET_KEY = ''
LOG_LOCATION = 'error.log'
UPLOADED_AVATARS_DEST = 'wire/static/img/avatar'
UPLOADED_IMAGES_DEST = 'wire/static/img/event'
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
# Get a key from http://code.google.com/apis/maps/signup.html
GMAPS_KEY = ''
STATIC_PATH = '/'

try:
    from wire.local_settings import *
except ImportError:
    pass