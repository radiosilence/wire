from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, ClassVar, Generic, TypeVar, cast

import redis
from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict, Field, field_validator

from wire.config import settings

logger = logging.getLogger(__name__)

T = TypeVar("T", bound="BaseModel")


class ModelError(Exception):
    """Base exception for model errors."""
    pass


class ValidationError(ModelError):
    """Raised when model validation fails."""
    pass


class NotFoundError(ModelError):
    """Raised when a model is not found."""
    pass


class RedisConnection:
    """Singleton Redis connection manager."""
    
    _instance: RedisConnection | None = None
    _client: redis.Redis | None = None
    
    def __new__(cls) -> RedisConnection:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @property
    def client(self) -> redis.Redis:
        """Get Redis client instance."""
        if self._client is None:
            pool = redis.ConnectionPool.from_url(
                settings.redis_url,
                max_connections=settings.redis_connection_pool_size,
                decode_responses=True,
            )
            self._client = redis.Redis(connection_pool=pool)
            
            # Test connection
            try:
                self._client.ping()
                logger.info("Redis connection established")
            except redis.ConnectionError as e:
                logger.error(f"Failed to connect to Redis: {e}")
                raise
        
        return self._client
    
    def close(self) -> None:
        """Close Redis connection."""
        if self._client:
            self._client.close()
            self._client = None


class BaseModel(PydanticBaseModel, ABC):
    """Base model for all Redis-backed models."""
    
    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=True,
        json_encoders={
            datetime: lambda v: v.isoformat(),
        },
    )
    
    # Redis key prefix for this model
    _key_prefix: ClassVar[str] = ""
    _key_separator: ClassVar[str] = ":"
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    def __init__(self, **data: Any) -> None:
        """Initialize model with data."""
        super().__init__(**data)
        self._redis = RedisConnection().client
    
    @classmethod
    @abstractmethod
    def get_key_prefix(cls) -> str:
        """Get the Redis key prefix for this model type."""
        pass
    
    @abstractmethod
    def get_primary_key(self) -> str:
        """Get the primary key value for this instance."""
        pass
    
    def get_redis_key(self, suffix: str = "") -> str:
        """Get the full Redis key for this instance."""
        parts = [self.get_key_prefix(), self.get_primary_key()]
        if suffix:
            parts.append(suffix)
        return self._key_separator.join(parts)
    
    def exists(self) -> bool:
        """Check if this model exists in Redis."""
        return bool(self._redis.exists(self.get_redis_key()))
    
    def save(self) -> None:
        """Save model to Redis."""
        self.updated_at = datetime.now(timezone.utc)
        
        # Validate before saving
        self.validate()
        
        # Convert to dict and save
        data = self.model_dump(mode="json")
        
        # Use pipeline for atomic operations
        pipe = self._redis.pipeline()
        
        # Save as hash
        key = self.get_redis_key()
        pipe.hset(key, mapping=data)
        
        # Set expiration if needed
        if hasattr(self, "_ttl") and self._ttl:
            pipe.expire(key, self._ttl)
        
        # Execute pipeline
        pipe.execute()
        
        logger.debug(f"Saved {self.__class__.__name__} with key: {key}")
    
    def delete(self) -> None:
        """Delete model from Redis."""
        key = self.get_redis_key()
        deleted = self._redis.delete(key)
        
        if deleted:
            logger.debug(f"Deleted {self.__class__.__name__} with key: {key}")
        else:
            logger.warning(f"Attempted to delete non-existent key: {key}")
    
    @classmethod
    def load(cls: type[T], primary_key: str) -> T:
        """Load model from Redis by primary key."""
        redis_client = RedisConnection().client
        
        # Create temporary instance to get key
        temp = cls(primary_key=primary_key)  # type: ignore
        key = temp.get_redis_key()
        
        # Load data
        data = redis_client.hgetall(key)
        
        if not data:
            raise NotFoundError(f"{cls.__name__} with key '{key}' not found")
        
        # Convert data types
        processed_data = cls._process_redis_data(data)
        
        # Create instance
        return cls(**processed_data)
    
    @classmethod
    def _process_redis_data(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Process data from Redis, converting types as needed."""
        processed = {}
        
        for field_name, field_info in cls.model_fields.items():
            if field_name in data:
                value = data[field_name]
                
                # Handle datetime fields
                if field_info.annotation == datetime:
                    if isinstance(value, str):
                        processed[field_name] = datetime.fromisoformat(value)
                    else:
                        processed[field_name] = value
                
                # Handle boolean fields
                elif field_info.annotation == bool:
                    if isinstance(value, str):
                        processed[field_name] = value.lower() == "true"
                    else:
                        processed[field_name] = bool(value)
                
                # Handle int fields
                elif field_info.annotation == int:
                    processed[field_name] = int(value)
                
                # Handle float fields
                elif field_info.annotation == float:
                    processed[field_name] = float(value)
                
                # Handle JSON fields
                elif hasattr(field_info.annotation, "__origin__") and field_info.annotation.__origin__ in (list, dict):
                    if isinstance(value, str):
                        processed[field_name] = json.loads(value)
                    else:
                        processed[field_name] = value
                
                else:
                    processed[field_name] = value
        
        return processed
    
    def refresh(self) -> None:
        """Refresh model data from Redis."""
        fresh_data = self.load(self.get_primary_key())
        
        # Update current instance with fresh data
        for field_name, value in fresh_data.model_dump().items():
            setattr(self, field_name, value)
    
    def increment_field(self, field: str, amount: int = 1) -> int:
        """Atomically increment a numeric field."""
        key = self.get_redis_key()
        new_value = self._redis.hincrby(key, field, amount)
        
        # Update local value
        setattr(self, field, new_value)
        
        return new_value
    
    def add_to_set(self, set_name: str, *values: str) -> int:
        """Add values to a Redis set associated with this model."""
        key = self.get_redis_key(set_name)
        return self._redis.sadd(key, *values)
    
    def remove_from_set(self, set_name: str, *values: str) -> int:
        """Remove values from a Redis set associated with this model."""
        key = self.get_redis_key(set_name)
        return self._redis.srem(key, *values)
    
    def get_set_members(self, set_name: str) -> set[str]:
        """Get all members of a Redis set associated with this model."""
        key = self.get_redis_key(set_name)
        return cast(set[str], self._redis.smembers(key))
    
    def add_to_list(self, list_name: str, *values: str, prepend: bool = False) -> int:
        """Add values to a Redis list associated with this model."""
        key = self.get_redis_key(list_name)
        
        if prepend:
            return self._redis.lpush(key, *values)
        else:
            return self._redis.rpush(key, *values)
    
    def get_list_items(
        self,
        list_name: str,
        start: int = 0,
        end: int = -1,
    ) -> list[str]:
        """Get items from a Redis list associated with this model."""
        key = self.get_redis_key(list_name)
        return cast(list[str], self._redis.lrange(key, start, end))
    
    def add_to_sorted_set(
        self,
        set_name: str,
        mapping: dict[str, float],
    ) -> int:
        """Add items to a Redis sorted set with scores."""
        key = self.get_redis_key(set_name)
        return self._redis.zadd(key, mapping)
    
    def get_sorted_set_items(
        self,
        set_name: str,
        start: int = 0,
        end: int = -1,
        reverse: bool = False,
        with_scores: bool = False,
    ) -> list[str] | list[tuple[str, float]]:
        """Get items from a Redis sorted set."""
        key = self.get_redis_key(set_name)
        
        if reverse:
            result = self._redis.zrevrange(key, start, end, withscores=with_scores)
        else:
            result = self._redis.zrange(key, start, end, withscores=with_scores)
        
        return cast(list[str] | list[tuple[str, float]], result)
    
    def set_expiration(self, seconds: int) -> bool:
        """Set expiration time for this model."""
        key = self.get_redis_key()
        return bool(self._redis.expire(key, seconds))
    
    def get_ttl(self) -> int:
        """Get time to live in seconds."""
        key = self.get_redis_key()
        ttl = self._redis.ttl(key)
        return ttl if ttl >= 0 else 0
    
    @classmethod
    def find_all(
        cls: type[T],
        pattern: str | None = None,
        limit: int | None = None,
    ) -> list[T]:
        """Find all instances matching a pattern."""
        redis_client = RedisConnection().client
        
        # Build search pattern
        if pattern:
            search_pattern = f"{cls.get_key_prefix()}{cls._key_separator}{pattern}"
        else:
            search_pattern = f"{cls.get_key_prefix()}{cls._key_separator}*"
        
        # Find matching keys
        keys = []
        for key in redis_client.scan_iter(match=search_pattern, count=100):
            keys.append(key)
            if limit and len(keys) >= limit:
                break
        
        # Load instances
        instances = []
        for key in keys:
            try:
                # Extract primary key from Redis key
                prefix = f"{cls.get_key_prefix()}{cls._key_separator}"
                if key.startswith(prefix):
                    primary_key = key[len(prefix):].split(cls._key_separator)[0]
                    instance = cls.load(primary_key)
                    instances.append(instance)
            except NotFoundError:
                logger.warning(f"Key exists but failed to load: {key}")
                continue
        
        return instances
    
    def validate(self) -> None:
        """Validate model data."""
        # Pydantic handles basic validation
        # Subclasses can override for custom validation
        super().model_validate(self.model_dump())
    
    def to_dict(self) -> dict[str, Any]:
        """Convert model to dictionary."""
        return self.model_dump()
    
    def to_json(self) -> str:
        """Convert model to JSON string."""
        return self.model_dump_json()
    
    @classmethod
    def from_json(cls: type[T], json_str: str) -> T:
        """Create model from JSON string."""
        return cls.model_validate_json(json_str)