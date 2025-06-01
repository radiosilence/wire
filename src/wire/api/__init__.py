"""Wire API package."""

from wire.api.auth import router as auth_router
from wire.api.events import router as events_router
from wire.api.messages import router as messages_router
from wire.api.users import router as users_router
from wire.api.websocket import router as websocket_router

__all__ = [
    "auth_router",
    "events_router",
    "messages_router",
    "users_router",
    "websocket_router",
]