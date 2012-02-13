#!/usr/bin/env python2
from wire import create_app
app = create_app(debug=True)
print app.url_map
app.run(host='0.0.0.0')