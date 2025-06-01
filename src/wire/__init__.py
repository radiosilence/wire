from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from flask import Flask, Response, g, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException

from wire.config import settings
from wire.crypto import SecureRandom


def create_app(config_override: dict[str, Any] | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, instance_relative_config=True)
    
    # Load configuration
    configure_app(app, config_override)
    
    # Initialize extensions
    init_extensions(app)
    
    # Configure security
    configure_security(app)
    
    # Configure logging
    configure_logging(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register before/after request handlers
    register_request_handlers(app)
    
    return app


def configure_app(app: Flask, config_override: dict[str, Any] | None = None) -> None:
    """Configure Flask app with settings."""
    # Base configuration from settings
    app.config.from_mapping(
        SECRET_KEY=settings.secret_key.get_secret_value(),
        DEBUG=settings.debug,
        TESTING=settings.testing,
        
        # Session configuration
        SESSION_COOKIE_SECURE=settings.session_cookie_secure,
        SESSION_COOKIE_HTTPONLY=settings.session_cookie_httponly,
        SESSION_COOKIE_SAMESITE=settings.session_cookie_samesite,
        PERMANENT_SESSION_LIFETIME=settings.permanent_session_lifetime,
        
        # File upload configuration
        MAX_CONTENT_LENGTH=settings.max_upload_size,
        
        # Redis configuration
        REDIS_URL=settings.redis_url,
        
        # CORS configuration
        CORS_ORIGINS=settings.cors_origins,
        CORS_ALLOW_CREDENTIALS=settings.cors_allow_credentials,
        
        # Rate limiting
        RATELIMIT_ENABLED=settings.rate_limit_enabled,
        RATELIMIT_DEFAULT=settings.rate_limit_default,
        RATELIMIT_STORAGE_URL=settings.rate_limit_storage_url,
    )
    
    # Apply any config overrides
    if config_override:
        app.config.update(config_override)
    
    # Ensure instance folder exists
    app.instance_path = Path(app.instance_path)
    app.instance_path.mkdir(exist_ok=True)


def init_extensions(app: Flask) -> None:
    """Initialize Flask extensions."""
    # CORS
    CORS(
        app,
        origins=app.config["CORS_ORIGINS"],
        supports_credentials=app.config["CORS_ALLOW_CREDENTIALS"],
    )
    
    # Rate limiting
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[app.config["RATELIMIT_DEFAULT"]],
        storage_uri=app.config["RATELIMIT_STORAGE_URL"],
        enabled=app.config["RATELIMIT_ENABLED"],
    )
    app.extensions["limiter"] = limiter


def configure_security(app: Flask) -> None:
    """Configure security headers and policies."""
    
    @app.after_request
    def set_security_headers(response: Response) -> Response:
        """Set security headers on all responses."""
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


def configure_logging(app: Flask) -> None:
    """Configure application logging."""
    log_level = getattr(logging, settings.log_level)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=settings.log_format,
        handlers=[]
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(settings.log_format))
    
    # File handler (if configured)
    handlers = [console_handler]
    if settings.log_file:
        file_handler = logging.FileHandler(settings.log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(settings.log_format))
        handlers.append(file_handler)
    
    # Add handlers to Flask logger
    for handler in handlers:
        app.logger.addHandler(handler)
    
    app.logger.setLevel(log_level)
    
    # Log startup information
    app.logger.info(f"Wire application starting in {settings.environment} mode")


def register_blueprints(app: Flask) -> None:
    """Register application blueprints."""
    # Import blueprints here to avoid circular imports
    from wire.api import api_bp
    from wire.auth import auth_bp
    from wire.frontend import frontend_bp
    
    # API blueprint
    app.register_blueprint(
        api_bp,
        url_prefix=f"{settings.api_prefix}/{settings.api_version}"
    )
    
    # Authentication blueprint
    app.register_blueprint(auth_bp, url_prefix="/auth")
    
    # Frontend blueprint
    app.register_blueprint(frontend_bp, url_prefix="")


def register_error_handlers(app: Flask) -> None:
    """Register error handlers."""
    
    @app.errorhandler(400)
    def bad_request(error: HTTPException) -> tuple[Response, int]:
        """Handle bad request errors."""
        return jsonify({
            "error": "Bad Request",
            "message": str(error.description),
            "status": 400
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error: HTTPException) -> tuple[Response, int]:
        """Handle unauthorized errors."""
        return jsonify({
            "error": "Unauthorized",
            "message": "Authentication required",
            "status": 401
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error: HTTPException) -> tuple[Response, int]:
        """Handle forbidden errors."""
        return jsonify({
            "error": "Forbidden",
            "message": "You don't have permission to access this resource",
            "status": 403
        }), 403
    
    @app.errorhandler(404)
    def not_found(error: HTTPException) -> tuple[Response, int]:
        """Handle not found errors."""
        return jsonify({
            "error": "Not Found",
            "message": "The requested resource was not found",
            "status": 404
        }), 404
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error: HTTPException) -> tuple[Response, int]:
        """Handle rate limit errors."""
        return jsonify({
            "error": "Too Many Requests",
            "message": "Rate limit exceeded. Please try again later.",
            "status": 429
        }), 429
    
    @app.errorhandler(500)
    def internal_error(error: Exception) -> tuple[Response, int]:
        """Handle internal server errors."""
        app.logger.error(f"Internal error: {error}", exc_info=True)
        
        # Don't expose internal details in production
        if settings.is_production():
            message = "An internal error occurred"
        else:
            message = str(error)
        
        return jsonify({
            "error": "Internal Server Error",
            "message": message,
            "status": 500
        }), 500
    
    @app.errorhandler(Exception)
    def unhandled_exception(error: Exception) -> tuple[Response, int]:
        """Handle unhandled exceptions."""
        app.logger.error(f"Unhandled exception: {error}", exc_info=True)
        
        if settings.is_production():
            return jsonify({
                "error": "Internal Server Error",
                "message": "An unexpected error occurred",
                "status": 500
            }), 500
        else:
            return jsonify({
                "error": type(error).__name__,
                "message": str(error),
                "status": 500
            }), 500


def register_request_handlers(app: Flask) -> None:
    """Register before/after request handlers."""
    
    @app.before_request
    def before_request() -> None:
        """Execute before each request."""
        # Generate request ID for tracking
        g.request_id = SecureRandom.generate_hex(16)
        
        # Log request details
        app.logger.debug(
            f"Request {g.request_id}: {request.method} {request.path} "
            f"from {request.remote_addr}"
        )
    
    @app.after_request
    def after_request(response: Response) -> Response:
        """Execute after each request."""
        # Add request ID to response headers
        response.headers["X-Request-ID"] = g.get("request_id", "unknown")
        
        # Log response details
        app.logger.debug(
            f"Response {g.get('request_id', 'unknown')}: "
            f"{response.status_code} {response.content_length} bytes"
        )
        
        return response
    
    @app.teardown_appcontext
    def teardown_appcontext(error: Exception | None = None) -> None:
        """Clean up after request context."""
        if error:
            app.logger.error(f"Request teardown error: {error}")


# Re-export for convenience
__all__ = ["create_app", "settings"]