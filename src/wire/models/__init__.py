"""Wire models package."""

from wire.models.base import BaseModel, ModelError, ValidationError
from wire.models.contacts import (
    ContactExistsError,
    ContactInvalidError,
    Contacts,
)
from wire.models.event import (
    Event,
    EventCommentError,
    EventMustLoadError,
    EventNotFoundError,
    EventValidationError,
)
from wire.models.message import (
    Inbox,
    Message,
    MessageError,
    MessageValidationError,
)
from wire.models.thread import (
    DestroyedThreadError,
    InvalidRecipients,
    Thread,
    ThreadError,
)
from wire.models.timeline import Timeline
from wire.models.update import Update, UpdateError
from wire.models.user import User, UserExists, UserNotFoundError, UserValidationError

__all__ = [
    # Base
    "BaseModel",
    "ModelError",
    "ValidationError",
    # User
    "User",
    "UserValidationError",
    "UserNotFoundError",
    "UserExists",
    # Message
    "Message",
    "MessageValidationError",
    "MessageError",
    "Inbox",
    # Thread
    "Thread",
    "ThreadError",
    "InvalidRecipients",
    "DestroyedThreadError",
    # Contacts
    "Contacts",
    "ContactExistsError",
    "ContactInvalidError",
    # Event
    "Event",
    "EventValidationError",
    "EventNotFoundError",
    "EventCommentError",
    "EventMustLoadError",
    # Update
    "Update",
    "UpdateError",
    # Timeline
    "Timeline",
]