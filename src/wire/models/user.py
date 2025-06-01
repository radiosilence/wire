from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, ClassVar, Literal

from pydantic import EmailStr, Field, field_validator

from wire.crypto import hash_password, verify_password
from wire.models.base import BaseModel, ModelError, NotFoundError, ValidationError


class UserValidationError(ValidationError):
    """Raised when user validation fails."""
    pass


class UserNotFoundError(NotFoundError):
    """Raised when user is not found."""
    pass


class UserExists(ModelError):
    """Raised when attempting to create a user that already exists."""
    pass


class User(BaseModel):
    """User model with secure authentication."""
    
    # Model configuration
    _key_prefix: ClassVar[str] = "user"
    
    # User fields
    username: str = Field(
        ...,
        min_length=3,
        max_length=30,
        description="Unique username"
    )
    email: EmailStr = Field(..., description="User email address")
    display_name: str | None = Field(None, max_length=100, description="Display name")
    bio: str | None = Field(None, max_length=500, description="User biography")
    avatar_url: str | None = Field(None, description="Avatar image URL")
    
    # Security fields
    password_hash: str | None = Field(None, exclude=True, description="Hashed password")
    is_active: bool = Field(True, description="Whether user account is active")
    is_admin: bool = Field(False, description="Whether user has admin privileges")
    is_verified: bool = Field(False, description="Whether email is verified")
    
    # Privacy settings
    privacy_level: Literal["public", "contacts", "private"] = Field(
        "contacts",
        description="Profile visibility level"
    )
    allow_contact_requests: bool = Field(True, description="Allow contact requests")
    show_online_status: bool = Field(True, description="Show online status")
    
    # Security settings
    two_factor_enabled: bool = Field(False, description="2FA enabled")
    two_factor_secret: str | None = Field(None, exclude=True, description="2FA secret")
    
    # Activity tracking
    last_seen: datetime | None = Field(None, description="Last activity timestamp")
    last_login: datetime | None = Field(None, description="Last login timestamp")
    login_count: int = Field(0, description="Total login count")
    
    # Rate limiting
    failed_login_attempts: int = Field(0, description="Failed login attempts")
    last_failed_login: datetime | None = Field(None, description="Last failed login")
    
    # Relationships counters
    contacts_count: int = Field(0, description="Number of contacts")
    followers_count: int = Field(0, description="Number of followers")
    following_count: int = Field(0, description="Number of following")
    
    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format."""
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError(
                "Username can only contain letters, numbers, underscores, and hyphens"
            )
        return v.lower()
    
    @field_validator("password_hash")
    @classmethod
    def validate_password_hash(cls, v: str | None) -> str | None:
        """Ensure password hash is never empty if set."""
        if v is not None and not v:
            raise ValueError("Password hash cannot be empty")
        return v
    
    @classmethod
    def get_key_prefix(cls) -> str:
        """Get Redis key prefix for users."""
        return cls._key_prefix
    
    def get_primary_key(self) -> str:
        """Get primary key (username) for this user."""
        return self.username
    
    def set_password(self, password: str) -> None:
        """Set user password (hashed)."""
        if len(password) < 8:
            raise UserValidationError("Password must be at least 8 characters long")
        
        # Check password complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if not (has_upper and has_lower and has_digit):
            raise UserValidationError(
                "Password must contain uppercase, lowercase, and numeric characters"
            )
        
        self.password_hash = hash_password(password)
    
    def check_password(self, password: str) -> bool:
        """Verify password against hash."""
        if not self.password_hash:
            return False
        return verify_password(password, self.password_hash)
    
    def save(self) -> None:
        """Save user to database."""
        # Check if user already exists
        if not hasattr(self, "_is_update") and self.exists():
            raise UserExists(f"User '{self.username}' already exists")
        
        # Validate before saving
        self.validate()
        
        # Save user data
        super().save()
        
        # Add to users set
        self._redis.sadd("users:all", self.username)
        
        # Update email index
        self._redis.hset("users:email_index", self.email, self.username)
    
    def delete(self) -> None:
        """Delete user and all associated data."""
        # Remove from users set
        self._redis.srem("users:all", self.username)
        
        # Remove from email index
        self._redis.hdel("users:email_index", self.email)
        
        # Delete user data
        super().delete()
        
        # Delete associated data
        self._delete_user_data()
    
    def _delete_user_data(self) -> None:
        """Delete all user-associated data."""
        patterns = [
            f"user:{self.username}:*",
            f"timeline:{self.username}:*",
            f"inbox:{self.username}:*",
            f"contacts:{self.username}:*",
        ]
        
        for pattern in patterns:
            for key in self._redis.scan_iter(match=pattern):
                self._redis.delete(key)
    
    @classmethod
    def load_by_username(cls, username: str) -> User:
        """Load user by username."""
        try:
            return cls.load(username.lower())
        except NotFoundError:
            raise UserNotFoundError(f"User '{username}' not found")
    
    @classmethod
    def load_by_email(cls, email: str) -> User:
        """Load user by email address."""
        # Look up username by email
        username = cls._get_redis().hget("users:email_index", email.lower())
        
        if not username:
            raise UserNotFoundError(f"User with email '{email}' not found")
        
        return cls.load_by_username(username)
    
    @classmethod
    def _get_redis(cls) -> Any:
        """Get Redis client for class methods."""
        from wire.models.base import RedisConnection
        return RedisConnection().client
    
    def update_last_seen(self) -> None:
        """Update last seen timestamp."""
        self.last_seen = datetime.now(timezone.utc)
        self._redis.hset(self.get_redis_key(), "last_seen", self.last_seen.isoformat())
    
    def update_login(self) -> None:
        """Update login information."""
        self.last_login = datetime.now(timezone.utc)
        self.login_count = self.increment_field("login_count")
        self.failed_login_attempts = 0
        
        self._redis.hmset(self.get_redis_key(), {
            "last_login": self.last_login.isoformat(),
            "failed_login_attempts": 0,
        })
    
    def record_failed_login(self) -> None:
        """Record a failed login attempt."""
        self.failed_login_attempts = self.increment_field("failed_login_attempts")
        self.last_failed_login = datetime.now(timezone.utc)
        
        self._redis.hset(
            self.get_redis_key(),
            "last_failed_login",
            self.last_failed_login.isoformat()
        )
    
    def is_locked_out(self, max_attempts: int = 5, lockout_minutes: int = 30) -> bool:
        """Check if user is locked out due to failed login attempts."""
        if self.failed_login_attempts < max_attempts:
            return False
        
        if not self.last_failed_login:
            return False
        
        lockout_until = self.last_failed_login.timestamp() + (lockout_minutes * 60)
        return datetime.now(timezone.utc).timestamp() < lockout_until
    
    # Contact management
    def add_contact(self, contact_username: str) -> None:
        """Add a contact."""
        if contact_username == self.username:
            raise UserValidationError("Cannot add yourself as a contact")
        
        # Verify contact exists
        if not self._redis.exists(f"user:{contact_username}"):
            raise UserNotFoundError(f"User '{contact_username}' not found")
        
        # Add to contacts set
        added = self.add_to_set("contacts", contact_username)
        if added:
            self.contacts_count = self.increment_field("contacts_count")
            
            # Add to contact's followers
            self._redis.sadd(f"user:{contact_username}:followers", self.username)
            self._redis.hincrby(f"user:{contact_username}", "followers_count", 1)
    
    def remove_contact(self, contact_username: str) -> None:
        """Remove a contact."""
        removed = self.remove_from_set("contacts", contact_username)
        if removed:
            self.contacts_count = self.increment_field("contacts_count", -1)
            
            # Remove from contact's followers
            self._redis.srem(f"user:{contact_username}:followers", self.username)
            self._redis.hincrby(f"user:{contact_username}", "followers_count", -1)
    
    def get_contacts(self) -> set[str]:
        """Get all contacts."""
        return self.get_set_members("contacts")
    
    def get_followers(self) -> set[str]:
        """Get all followers."""
        return self.get_set_members("followers")
    
    def is_contact(self, username: str) -> bool:
        """Check if user is a contact."""
        return self._redis.sismember(self.get_redis_key("contacts"), username)
    
    def is_follower(self, username: str) -> bool:
        """Check if user is a follower."""
        return self._redis.sismember(self.get_redis_key("followers"), username)
    
    # Timeline methods
    def get_timeline_updates(self, limit: int = 50, offset: int = 0) -> list[str]:
        """Get timeline update IDs."""
        return self.get_sorted_set_items(
            "timeline",
            start=offset,
            end=offset + limit - 1,
            reverse=True,
        )
    
    def add_timeline_update(self, update_id: str, timestamp: float | None = None) -> None:
        """Add update to timeline."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).timestamp()
        
        self.add_to_sorted_set("timeline", {update_id: timestamp})
    
    # Mention methods
    def get_mentions(self, limit: int = 50, offset: int = 0) -> list[str]:
        """Get mention update IDs."""
        return self.get_sorted_set_items(
            "mentions",
            start=offset,
            end=offset + limit - 1,
            reverse=True,
        )
    
    def add_mention(self, update_id: str, timestamp: float | None = None) -> None:
        """Add mention."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).timestamp()
        
        self.add_to_sorted_set("mentions", {update_id: timestamp})
        self.increment_field("unread_mentions_count")
    
    def reset_mentions(self) -> None:
        """Mark all mentions as read."""
        self._redis.hset(self.get_redis_key(), "unread_mentions_count", 0)
    
    # Event methods
    def set_attending(self, event_id: str) -> None:
        """Mark as attending an event."""
        self.add_to_set("events:attending", event_id)
        self.remove_from_set("events:maybe", event_id)
        self.remove_from_set("events:not_attending", event_id)
    
    def set_maybe(self, event_id: str) -> None:
        """Mark as maybe attending an event."""
        self.add_to_set("events:maybe", event_id)
        self.remove_from_set("events:attending", event_id)
        self.remove_from_set("events:not_attending", event_id)
    
    def set_not_attending(self, event_id: str) -> None:
        """Mark as not attending an event."""
        self.add_to_set("events:not_attending", event_id)
        self.remove_from_set("events:attending", event_id)
        self.remove_from_set("events:maybe", event_id)
    
    def get_event_state(self, event_id: str) -> Literal["attending", "maybe", "not_attending", "unknown"]:
        """Get attendance state for an event."""
        if self._redis.sismember(self.get_redis_key("events:attending"), event_id):
            return "attending"
        elif self._redis.sismember(self.get_redis_key("events:maybe"), event_id):
            return "maybe"
        elif self._redis.sismember(self.get_redis_key("events:not_attending"), event_id):
            return "not_attending"
        else:
            return "unknown"
    
    @classmethod
    def search(cls, query: str, limit: int = 20) -> list[User]:
        """Search for users by username or email."""
        query = query.lower()
        results = []
        
        # Search through all users
        for username in cls._get_redis().smembers("users:all"):
            if query in username:
                try:
                    user = cls.load_by_username(username)
                    results.append(user)
                    if len(results) >= limit:
                        break
                except UserNotFoundError:
                    continue
        
        return results
    
    def to_public_dict(self) -> dict[str, Any]:
        """Convert to dictionary with only public fields."""
        return {
            "username": self.username,
            "display_name": self.display_name,
            "bio": self.bio,
            "avatar_url": self.avatar_url,
            "is_verified": self.is_verified,
            "created_at": self.created_at.isoformat(),
            "last_seen": self.last_seen.isoformat() if self.last_seen and self.show_online_status else None,
            "contacts_count": self.contacts_count,
            "followers_count": self.followers_count,
        }