#!/usr/bin/env python
import sys
sys.path[0:0] = [
    '/var/www/apps/wire/'
]

from wire import app

app.run()
