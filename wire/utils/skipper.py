from werkzeug import Request, abort
from werkzeug.exceptions import NotFound

def ignore_ico(app, static_types):
    @Request.application
    def _app(request):
        if request.path.split('.')[-1] in static_types:
            return NotFound()
        return app
    return _app