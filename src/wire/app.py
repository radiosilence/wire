from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

import redis.asyncio as redis
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, ORJSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from wire.config import settings
from wire.connections import ConnectionManager
from wire.crypto import SecureRandom

logger = logging.getLogger(__name__)


class RedisPool:
    """Async Redis connection pool manager."""
    
    _pool: redis.ConnectionPool | None = None
    
    @classmethod
    async def get_pool(cls) -> redis.ConnectionPool:
        """Get or create Redis connection pool."""
        if cls._pool is None:
            cls._pool = redis.ConnectionPool.from_url(
                settings.redis_url,
                max_connections=settings.redis_connection_pool_size,
                decode_responses=True,
            )
        return cls._pool
    
    @classmethod
    async def get_client(cls) -> redis.Redis:
        """Get Redis client from pool."""
        pool = await cls.get_pool()
        return redis.Redis(connection_pool=pool)
    
    @classmethod
    async def close(cls) -> None:
        """Close Redis pool."""
        if cls._pool:
            await cls._pool.disconnect()
            cls._pool = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    # Startup
    logger.info(f"Starting Wire application in {settings.environment} mode")
    
    # Initialize Redis pool
    redis_client = await RedisPool.get_client()
    await redis_client.ping()
    logger.info("Redis connection established")
    
    # Initialize connection manager
    app.state.connections = ConnectionManager()
    
    # Set app state
    app.state.redis = redis_client
    
    yield
    
    # Shutdown
    logger.info("Shutting down Wire application")
    
    # Close all WebSocket connections
    await app.state.connections.disconnect_all()
    
    # Close Redis pool
    await RedisPool.close()


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="Wire Secure Messaging",
        description="End-to-end encrypted messaging platform for activists",
        version="2.0.0",
        lifespan=lifespan,
        default_response_class=ORJSONResponse,
        docs_url="/api/docs" if not settings.is_production() else None,
        redoc_url="/api/redoc" if not settings.is_production() else None,
        openapi_url="/api/openapi.json" if not settings.is_production() else None,
    )
    
    # Configure middleware
    configure_middleware(app)
    
    # Configure rate limiting
    configure_rate_limiting(app)
    
    # Register routers
    register_routers(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    return app


def configure_middleware(app: FastAPI) -> None:
    """Configure application middleware."""
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Process-Time"],
    )
    
    # Gzip compression
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # Trusted host (security)
    if settings.is_production():
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["*.wire.secure", "wire.secure"]
        )
    
    # Request ID middleware
    @app.middleware("http")
    async def add_request_id(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or SecureRandom.generate_hex(16)
        request.state.request_id = request_id
        
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        
        return response
    
    # Process time middleware
    @app.middleware("http")
    async def add_process_time(request: Request, call_next):
        start_time = asyncio.get_event_loop().time()
        response = await call_next(request)
        process_time = asyncio.get_event_loop().time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response
    
    # Security headers middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        
        # Strict Transport Security
        if settings.is_production():
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        
        # Content Security Policy
        if settings.csp_enabled:
            csp_directives = [
                f"{key} {value}" for key, value in settings.csp_directives.items()
            ]
            response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
        
        # Additional security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), "
            "payment=(), usb=()"
        )
        
        return response


def configure_rate_limiting(app: FastAPI) -> None:
    """Configure rate limiting."""
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[settings.rate_limit_default],
        enabled=settings.rate_limit_enabled,
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def register_routers(app: FastAPI) -> None:
    """Register API routers."""
    from wire.api.auth import router as auth_router
    from wire.api.events import router as events_router
    from wire.api.messages import router as messages_router
    from wire.api.users import router as users_router
    from wire.api.websocket import router as ws_router
    
    # API v1 routers
    api_prefix = f"{settings.api_prefix}/{settings.api_version}"
    
    app.include_router(auth_router, prefix=f"{api_prefix}/auth", tags=["auth"])
    app.include_router(users_router, prefix=f"{api_prefix}/users", tags=["users"])
    app.include_router(messages_router, prefix=f"{api_prefix}/messages", tags=["messages"])
    app.include_router(events_router, prefix=f"{api_prefix}/events", tags=["events"])
    app.include_router(ws_router, prefix="/ws", tags=["websocket"])
    
    # Health check endpoints
    @app.get("/health", tags=["health"])
    async def health_check():
        """Basic health check."""
        return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}
    
    @app.get("/health/ready", tags=["health"])
    async def readiness_check(request: Request):
        """Readiness check including Redis."""
        try:
            # Check Redis
            await request.app.state.redis.ping()
            
            return {
                "status": "ready",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "checks": {
                    "redis": "healthy"
                }
            }
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Service not ready: {str(e)}"
            )


def register_error_handlers(app: FastAPI) -> None:
    """Register custom error handlers."""
    
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handle HTTP exceptions."""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.detail,
                "status_code": exc.status_code,
                "request_id": getattr(request.state, "request_id", "unknown"),
            },
        )
    
    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError):
        """Handle validation errors."""
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Validation error",
                "detail": str(exc),
                "request_id": getattr(request.state, "request_id", "unknown"),
            },
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle uncaught exceptions."""
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        
        # Don't expose internal errors in production
        if settings.is_production():
            detail = "An internal error occurred"
        else:
            detail = str(exc)
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal server error",
                "detail": detail,
                "request_id": getattr(request.state, "request_id", "unknown"),
            },
        )


# WebSocket endpoint for real-time messaging
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    """WebSocket endpoint for real-time communication."""
    await websocket.accept()
    
    # Add connection to manager
    await app.state.connections.connect(user_id, websocket)
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_json()
            
            # Process different message types
            message_type = data.get("type")
            
            if message_type == "ping":
                # Respond to ping
                await websocket.send_json({"type": "pong"})
            
            elif message_type == "message":
                # Handle direct message
                recipient = data.get("recipient")
                content = data.get("content")
                
                # Encrypt and store message
                # ... message processing logic ...
                
                # Send to recipient if online
                await app.state.connections.send_to_user(
                    recipient,
                    {
                        "type": "message",
                        "from": user_id,
                        "content": content,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            
            elif message_type == "typing":
                # Handle typing indicator
                recipient = data.get("recipient")
                await app.state.connections.send_to_user(
                    recipient,
                    {
                        "type": "typing",
                        "from": user_id,
                    }
                )
            
            elif message_type == "presence":
                # Update user presence
                status = data.get("status", "online")
                await app.state.connections.update_presence(user_id, status)
    
    except WebSocketDisconnect:
        # Remove connection
        await app.state.connections.disconnect(user_id)
        
        # Update user status
        await app.state.connections.update_presence(user_id, "offline")
    
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")
        await app.state.connections.disconnect(user_id)


# Create app instance
app = create_app()