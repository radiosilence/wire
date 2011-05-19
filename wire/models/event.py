import redis, json
from wire.utils.redis import autoinc

class Event:
    def __init__(self, redis=False, user=False):
        self.redis = redis
        self.user = user
        self.data = {
            'image': 'default.png',
        }
        self.validation_errors = []
        self.key = False

    def update(self, data):
        form_fields = [
            'name',
            'date',
            'time',
            'description'
        ]
        for field in form_fields:
            try:
                self.data[field] = data[field]
            except KeyError:
                self.data[field] = ""
    
    def save(self):
        r = self.redis
        self._validate()

        if not self.key:
            self.data['creator'] = self.user.username
            self.key = autoinc(self.redis, 'event')
            r.lpush('_list:events', self.key)
            r.lpush('user:%s:events' % self.user.key, self.key)
        
        r.set('event:%s' % self.key, json.dumps(self.data))

    def load(self, event_id):
        r = self.redis

        if r.exists('event:%s' % event_id):
            self.key = event_id
            self.data = json.loads(r.get('event:%s' % self.key))
        else:
            raise EventNotFoundError()

    def _validate(self):
        if len(self.data['name']) < 1:
            self.validation_errors.append("Event name must be set.")

        if len(self.validation_errors) > 0:
            raise EventValidationError()
    
class EventNotFoundError(Exception):
    pass
class EventValidationError(Exception):
    pass