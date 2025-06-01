from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Literal

from pydantic import Field, field_validator

from wire.crypto import EncryptedMessage, SymmetricEncryption
from wire.models.async_base import AsyncBaseModel, ModelError, NotFoundError, ValidationError


class MessageType(str, Enum):
    """Message types."""
    
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"
    VOICE = "voice"
    VIDEO = "video"
    LOCATION = "location"
    CONTACT = "contact"
    SYSTEM = "system"


class MessageStatus(str, Enum):
    """Message delivery status."""
    
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"


class MessageValidationError(ValidationError):
    """Raised when message validation fails."""
    pass


class MessageError(ModelError):
    """General message error."""
    pass


class Message(AsyncBaseModel):
    """Encrypted message model."""
    
    _key_prefix: ClassVar[str] = "message"
    
    # Message ID
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    
    # Thread/conversation ID
    thread_id: str = Field(..., description="Thread this message belongs to")
    
    # Sender
    sender_id: str = Field(..., description="User ID of sender")
    
    # Message type
    message_type: MessageType = Field(MessageType.TEXT, description="Type of message")
    
    # Encrypted content
    encrypted_content: str = Field(..., description="Encrypted message content")
    encryption_algorithm: str = Field("AES-256-GCM", description="Encryption algorithm used")
    
    # For group messages - per-recipient encrypted keys
    recipient_keys: dict[str, str] = Field(
        default_factory=dict,
        description="Per-recipient encrypted keys"
    )
    
    # Metadata (not encrypted)
    reply_to_id: str | None = Field(None, description="ID of message being replied to")
    forwarded_from_id: str | None = Field(None, description="Original message ID if forwarded")
    edited: bool = Field(False, description="Whether message has been edited")
    edited_at: datetime | None = Field(None, description="When message was edited")
    
    # Delivery status per recipient
    delivery_status: dict[str, MessageStatus] = Field(
        default_factory=dict,
        description="Delivery status per recipient"
    )
    
    # Reactions
    reactions: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Reactions by emoji -> list of user IDs"
    )
    
    # Attachments metadata (encrypted separately)
    attachments: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Attachment metadata"
    )
    
    # Deletion
    deleted: bool = Field(False, description="Whether message is deleted")
    deleted_at: datetime | None = Field(None, description="When message was deleted")
    deleted_for: list[str] = Field(
        default_factory=list,
        description="User IDs who deleted this message"
    )
    
    # Expiration
    expires_at: datetime | None = Field(None, description="Message expiration time")
    
    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        """Validate message ID format."""
        try:
            uuid.UUID(v)
        except ValueError:
            raise ValueError("Invalid message ID format")
        return v
    
    @classmethod
    def get_key_prefix(cls) -> str:
        """Get Redis key prefix."""
        return cls._key_prefix
    
    def get_primary_key(self) -> str:
        """Get primary key."""
        return self.id
    
    async def send(
        self,
        content: str,
        shared_key: bytes,
        recipient_ids: list[str] | None = None,
    ) -> None:
        """Encrypt and send message."""
        # Validate
        if not content:
            raise MessageValidationError("Message content cannot be empty")
        
        if len(content) > 10000:  # 10KB limit for text
            raise MessageValidationError("Message content too large")
        
        # Encrypt content
        crypto = SymmetricEncryption()
        encrypted = crypto.encrypt(content, shared_key)
        self.encrypted_content = encrypted.to_base64()
        
        # Set initial delivery status
        if recipient_ids:
            for recipient_id in recipient_ids:
                self.delivery_status[recipient_id] = MessageStatus.PENDING
        
        # Save message
        await self.save()
        
        # Add to thread
        await self._add_to_thread()
        
        # Add to recipient inboxes
        if recipient_ids:
            await self._deliver_to_recipients(recipient_ids)
    
    async def decrypt_content(self, shared_key: bytes) -> str:
        """Decrypt message content."""
        if not self.encrypted_content:
            raise MessageError("No encrypted content")
        
        crypto = SymmetricEncryption()
        encrypted = EncryptedMessage.from_base64(self.encrypted_content)
        
        try:
            decrypted = crypto.decrypt(encrypted, shared_key)
            return decrypted.decode("utf-8")
        except Exception as e:
            raise MessageError(f"Failed to decrypt message: {e}")
    
    async def mark_delivered(self, recipient_id: str) -> None:
        """Mark message as delivered to recipient."""
        redis_client = await self._get_instance_redis()
        
        self.delivery_status[recipient_id] = MessageStatus.DELIVERED
        
        # Update in Redis
        await redis_client.hset(
            self.get_redis_key(),
            "delivery_status",
            self.model_dump_json(include={"delivery_status"})
        )
        
        # Notify sender
        await self._notify_delivery_status(recipient_id, MessageStatus.DELIVERED)
    
    async def mark_read(self, recipient_id: str) -> None:
        """Mark message as read by recipient."""
        redis_client = await self._get_instance_redis()
        
        self.delivery_status[recipient_id] = MessageStatus.READ
        
        # Update in Redis
        await redis_client.hset(
            self.get_redis_key(),
            "delivery_status",
            self.model_dump_json(include={"delivery_status"})
        )
        
        # Notify sender
        await self._notify_delivery_status(recipient_id, MessageStatus.READ)
    
    async def add_reaction(self, user_id: str, emoji: str) -> None:
        """Add reaction to message."""
        if len(emoji) > 10:  # Basic emoji validation
            raise MessageValidationError("Invalid emoji")
        
        redis_client = await self._get_instance_redis()
        
        if emoji not in self.reactions:
            self.reactions[emoji] = []
        
        if user_id not in self.reactions[emoji]:
            self.reactions[emoji].append(user_id)
        
        # Update in Redis
        await redis_client.hset(
            self.get_redis_key(),
            "reactions",
            self.model_dump_json(include={"reactions"})
        )
        
        # Notify thread participants
        await self._notify_reaction(user_id, emoji, "add")
    
    async def remove_reaction(self, user_id: str, emoji: str) -> None:
        """Remove reaction from message."""
        redis_client = await self._get_instance_redis()
        
        if emoji in self.reactions and user_id in self.reactions[emoji]:
            self.reactions[emoji].remove(user_id)
            
            if not self.reactions[emoji]:
                del self.reactions[emoji]
        
        # Update in Redis
        await redis_client.hset(
            self.get_redis_key(),
            "reactions",
            self.model_dump_json(include={"reactions"})
        )
        
        # Notify thread participants
        await self._notify_reaction(user_id, emoji, "remove")
    
    async def edit(
        self,
        new_content: str,
        shared_key: bytes,
        editor_id: str,
    ) -> None:
        """Edit message content."""
        if editor_id != self.sender_id:
            raise MessageError("Only sender can edit message")
        
        if self.deleted:
            raise MessageError("Cannot edit deleted message")
        
        # Encrypt new content
        crypto = SymmetricEncryption()
        encrypted = crypto.encrypt(new_content, shared_key)
        self.encrypted_content = encrypted.to_base64()
        
        self.edited = True
        self.edited_at = datetime.now(timezone.utc)
        
        await self.save()
        
        # Notify recipients
        await self._notify_edit()
    
    async def delete(self, deleter_id: str | None = None) -> None:
        """Delete message."""
        redis_client = await self._get_instance_redis()
        
        if deleter_id:
            # Delete for specific user
            if deleter_id not in self.deleted_for:
                self.deleted_for.append(deleter_id)
            
            await redis_client.hset(
                self.get_redis_key(),
                "deleted_for",
                self.model_dump_json(include={"deleted_for"})
            )
        else:
            # Delete for everyone (only sender can do this)
            self.deleted = True
            self.deleted_at = datetime.now(timezone.utc)
            
            await self.save()
            
            # Notify all recipients
            await self._notify_deletion()
    
    async def _add_to_thread(self) -> None:
        """Add message to thread."""
        redis_client = await self._get_instance_redis()
        
        # Add to thread messages sorted set
        thread_key = f"thread:{self.thread_id}:messages"
        score = self.created_at.timestamp()
        await redis_client.zadd(thread_key, {self.id: score})
        
        # Update thread last message
        await redis_client.hset(
            f"thread:{self.thread_id}",
            mapping={
                "last_message_id": self.id,
                "last_message_at": self.created_at.isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    
    async def _deliver_to_recipients(self, recipient_ids: list[str]) -> None:
        """Deliver message to recipient inboxes."""
        redis_client = await self._get_instance_redis()
        
        timestamp = self.created_at.timestamp()
        
        # Use pipeline for efficiency
        async with redis_client.pipeline() as pipe:
            for recipient_id in recipient_ids:
                # Add to inbox
                inbox_key = f"user:{recipient_id}:inbox"
                await pipe.zadd(inbox_key, {self.id: timestamp})
                
                # Increment unread count
                await pipe.hincrby(f"user:{recipient_id}:inbox:unread", self.thread_id, 1)
                
                # Update delivery status
                await pipe.hset(
                    self.get_redis_key(),
                    f"delivery_status:{recipient_id}",
                    MessageStatus.SENT
                )
            
            await pipe.execute()
    
    async def _notify_delivery_status(
        self,
        recipient_id: str,
        status: MessageStatus,
    ) -> None:
        """Notify about delivery status change."""
        # This would integrate with WebSocket connections
        # to send real-time updates
        pass
    
    async def _notify_reaction(
        self,
        user_id: str,
        emoji: str,
        action: Literal["add", "remove"],
    ) -> None:
        """Notify about reaction change."""
        # This would integrate with WebSocket connections
        pass
    
    async def _notify_edit(self) -> None:
        """Notify about message edit."""
        # This would integrate with WebSocket connections
        pass
    
    async def _notify_deletion(self) -> None:
        """Notify about message deletion."""
        # This would integrate with WebSocket connections
        pass
    
    @classmethod
    async def get_thread_messages(
        cls,
        thread_id: str,
        limit: int = 50,
        before_timestamp: float | None = None,
    ) -> list[Message]:
        """Get messages from a thread."""
        redis_client = await cls._get_redis()
        
        thread_key = f"thread:{thread_id}:messages"
        
        # Get message IDs from sorted set
        if before_timestamp:
            message_ids = await redis_client.zrevrangebyscore(
                thread_key,
                max=before_timestamp,
                min=0,
                start=0,
                num=limit,
            )
        else:
            message_ids = await redis_client.zrevrange(
                thread_key,
                start=0,
                end=limit - 1,
            )
        
        # Load messages
        messages = []
        for message_id in message_ids:
            try:
                message = await cls.load(message_id)
                messages.append(message)
            except NotFoundError:
                # Message might have been deleted
                continue
        
        return messages
    
    def to_dict(self, include_encrypted: bool = False) -> dict[str, Any]:
        """Convert to dictionary."""
        data = super().to_dict()
        
        # Remove encrypted content unless explicitly requested
        if not include_encrypted:
            data.pop("encrypted_content", None)
            data.pop("recipient_keys", None)
        
        return data