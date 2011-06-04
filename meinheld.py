from meinheld import server
from wire import app

server.listen(("0.0.0.0", 8000))
server.run(app)
