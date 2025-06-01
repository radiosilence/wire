import asyncio
import json
import pytest
from datetime import datetime
from typing import AsyncGenerator

import httpx
import websockets
from fastapi.testclient import TestClient
from jose import jwt

from wire.app import app
from wire.config import settings
from wire.crypto import SymmetricEncryption, AsymmetricEncryption
from wire.models.async_user import AsyncUser


@pytest.fixture
async def test_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Create async test client."""
    async with httpx.AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
async def authenticated_client(test_client: httpx.AsyncClient) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Create authenticated test client."""
    # Create test user
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "TestPass123!"
    }
    
    # Register user
    await test_client.post("/api/v1/auth/register", json=user_data)
    
    # Login
    login_response = await test_client.post(
        "/api/v1/auth/token",
        data={"username": user_data["username"], "password": user_data["password"]}
    )
    
    token_data = login_response.json()
    
    # Add auth header
    test_client.headers["Authorization"] = f"Bearer {token_data['access_token']}"
    
    yield test_client


class TestAuthenticationFlow:
    """Test authentication endpoints."""
    
    async def test_user_registration(self, test_client: httpx.AsyncClient):
        """Test user registration flow."""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "SecurePass123!",
            "display_name": "New User"
        }
        
        response = await test_client.post("/api/v1/auth/register", json=user_data)
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == user_data["username"]
        assert data["email"] == user_data["email"]
        assert data["display_name"] == user_data["display_name"]
        assert "password" not in data
    
    async def test_user_login(self, test_client: httpx.AsyncClient):
        """Test user login flow."""
        # First register
        user_data = {
            "username": "logintest",
            "email": "login@example.com",
            "password": "LoginPass123!"
        }
        
        await test_client.post("/api/v1/auth/register", json=user_data)
        
        # Then login
        login_response = await test_client.post(
            "/api/v1/auth/token",
            data={"username": user_data["username"], "password": user_data["password"]}
        )
        
        assert login_response.status_code == 200
        token_data = login_response.json()
        
        assert "access_token" in token_data
        assert "refresh_token" in token_data
        assert token_data["token_type"] == "bearer"
        
        # Verify JWT token
        payload = jwt.decode(
            token_data["access_token"],
            settings.secret_key.get_secret_value(),
            algorithms=["HS256"]
        )
        assert payload["sub"] == user_data["username"]
    
    async def test_invalid_login(self, test_client: httpx.AsyncClient):
        """Test login with invalid credentials."""
        response = await test_client.post(
            "/api/v1/auth/token",
            data={"username": "nonexistent", "password": "wrongpass"}
        )
        
        assert response.status_code == 401
    
    async def test_token_refresh(self, test_client: httpx.AsyncClient):
        """Test token refresh flow."""
        # Register and login
        user_data = {
            "username": "refreshtest",
            "email": "refresh@example.com",
            "password": "RefreshPass123!"
        }
        
        await test_client.post("/api/v1/auth/register", json=user_data)
        
        login_response = await test_client.post(
            "/api/v1/auth/token",
            data={"username": user_data["username"], "password": user_data["password"]}
        )
        
        token_data = login_response.json()
        
        # Refresh token
        refresh_response = await test_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": token_data["refresh_token"]}
        )
        
        assert refresh_response.status_code == 200
        new_token_data = refresh_response.json()
        
        assert new_token_data["access_token"] != token_data["access_token"]
        assert new_token_data["refresh_token"] == token_data["refresh_token"]


class TestUserManagement:
    """Test user management endpoints."""
    
    async def test_get_current_user(self, authenticated_client: httpx.AsyncClient):
        """Test getting current user info."""
        response = await authenticated_client.get("/api/v1/auth/me")
        
        assert response.status_code == 200
        user_data = response.json()
        
        assert user_data["username"] == "testuser"
        assert user_data["email"] == "test@example.com"
        assert "password" not in user_data
    
    async def test_change_password(self, authenticated_client: httpx.AsyncClient):
        """Test password change."""
        change_data = {
            "current_password": "TestPass123!",
            "new_password": "NewSecurePass456!"
        }
        
        response = await authenticated_client.post(
            "/api/v1/auth/change-password",
            json=change_data
        )
        
        assert response.status_code == 200
        
        # Verify old password no longer works
        login_response = await authenticated_client.post(
            "/api/v1/auth/token",
            data={"username": "testuser", "password": "TestPass123!"}
        )
        assert login_response.status_code == 401
        
        # Verify new password works
        login_response = await authenticated_client.post(
            "/api/v1/auth/token",
            data={"username": "testuser", "password": "NewSecurePass456!"}
        )
        assert login_response.status_code == 200


class TestMessaging:
    """Test messaging functionality."""
    
    async def test_send_direct_message(self, authenticated_client: httpx.AsyncClient):
        """Test sending a direct message."""
        # Create recipient
        recipient_data = {
            "username": "recipient",
            "email": "recipient@example.com",
            "password": "RecipientPass123!"
        }
        
        await authenticated_client.post("/api/v1/auth/register", json=recipient_data)
        
        # Create thread
        thread_response = await authenticated_client.post(
            "/api/v1/messages/threads",
            json={"recipients": ["recipient"], "title": "Test Thread"}
        )
        
        assert thread_response.status_code == 200
        thread_data = thread_response.json()
        thread_id = thread_data["id"]
        
        # Send message
        message_data = {
            "thread_id": thread_id,
            "content": "Hello, this is a test message!",
            "message_type": "text"
        }
        
        response = await authenticated_client.post(
            "/api/v1/messages",
            json=message_data
        )
        
        assert response.status_code == 200
        message = response.json()
        
        assert message["sender_id"] == "testuser"
        assert message["thread_id"] == thread_id
        assert "encrypted_content" in message
        assert message["message_type"] == "text"
    
    async def test_get_thread_messages(self, authenticated_client: httpx.AsyncClient):
        """Test retrieving messages from a thread."""
        # Create thread and send messages
        thread_response = await authenticated_client.post(
            "/api/v1/messages/threads",
            json={"recipients": ["testuser"], "title": "Self Thread"}
        )
        
        thread_id = thread_response.json()["id"]
        
        # Send multiple messages
        for i in range(5):
            await authenticated_client.post(
                "/api/v1/messages",
                json={
                    "thread_id": thread_id,
                    "content": f"Message {i}",
                    "message_type": "text"
                }
            )
        
        # Get messages
        response = await authenticated_client.get(
            f"/api/v1/messages/threads/{thread_id}/messages"
        )
        
        assert response.status_code == 200
        messages = response.json()
        
        assert len(messages) == 5
        assert all(msg["thread_id"] == thread_id for msg in messages)


class TestWebSocket:
    """Test WebSocket functionality."""
    
    async def test_websocket_connection(self):
        """Test WebSocket connection and messaging."""
        # Create test users
        async with httpx.AsyncClient(app=app, base_url="http://test") as client:
            # Register users
            await client.post("/api/v1/auth/register", json={
                "username": "wsuser1",
                "email": "ws1@example.com",
                "password": "WSPass123!"
            })
            
            await client.post("/api/v1/auth/register", json={
                "username": "wsuser2",
                "email": "ws2@example.com",
                "password": "WSPass123!"
            })
        
        # Connect both users via WebSocket
        uri = "ws://localhost:8000/ws"
        
        async with websockets.connect(f"{uri}/wsuser1") as ws1, \
                   websockets.connect(f"{uri}/wsuser2") as ws2:
            
            # User 1 sends message to User 2
            message = {
                "type": "message",
                "recipient": "wsuser2",
                "content": "Hello via WebSocket!"
            }
            
            await ws1.send(json.dumps(message))
            
            # User 2 should receive the message
            received = await asyncio.wait_for(ws2.recv(), timeout=5.0)
            received_data = json.loads(received)
            
            assert received_data["type"] == "message"
            assert received_data["from"] == "wsuser1"
            assert received_data["content"] == "Hello via WebSocket!"
    
    async def test_websocket_presence(self):
        """Test presence updates via WebSocket."""
        uri = "ws://localhost:8000/ws"
        
        async with websockets.connect(f"{uri}/presenceuser") as ws:
            # Send presence update
            presence = {
                "type": "presence",
                "status": "away"
            }
            
            await ws.send(json.dumps(presence))
            
            # Send ping to verify connection
            ping = {"type": "ping"}
            await ws.send(json.dumps(ping))
            
            # Should receive pong
            response = await asyncio.wait_for(ws.recv(), timeout=5.0)
            response_data = json.loads(response)
            
            assert response_data["type"] == "pong"


class TestEncryption:
    """Test end-to-end encryption."""
    
    async def test_message_encryption(self):
        """Test that messages are properly encrypted."""
        # Generate keys for two users
        crypto = AsymmetricEncryption()
        alice_private, alice_public = crypto.generate_keypair()
        bob_private, bob_public = crypto.generate_keypair()
        
        # Derive shared secret
        shared_secret = crypto.derive_shared_secret(alice_private, bob_public)
        
        # Create message
        plaintext = "This is a secret message"
        sym_crypto = SymmetricEncryption()
        
        # Encrypt
        encrypted = sym_crypto.encrypt(plaintext, shared_secret)
        
        # Verify it's encrypted
        assert encrypted.ciphertext != plaintext.encode()
        
        # Bob can decrypt with same shared secret
        bob_shared_secret = crypto.derive_shared_secret(bob_private, alice_public)
        decrypted = sym_crypto.decrypt(encrypted, bob_shared_secret)
        
        assert decrypted.decode("utf-8") == plaintext


class TestSecurity:
    """Test security features."""
    
    async def test_rate_limiting(self, test_client: httpx.AsyncClient):
        """Test rate limiting on auth endpoints."""
        # Make many rapid requests
        responses = []
        for i in range(150):  # Exceed default rate limit
            response = await test_client.post(
                "/api/v1/auth/token",
                data={"username": "test", "password": "wrong"}
            )
            responses.append(response.status_code)
        
        # Should have some 429 responses
        assert 429 in responses
    
    async def test_security_headers(self, test_client: httpx.AsyncClient):
        """Test security headers are present."""
        response = await test_client.get("/health")
        
        headers = response.headers
        
        # Check security headers
        assert "X-Content-Type-Options" in headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        
        assert "X-Frame-Options" in headers
        assert headers["X-Frame-Options"] == "DENY"
        
        assert "X-XSS-Protection" in headers
        assert "Referrer-Policy" in headers
        
        if settings.csp_enabled:
            assert "Content-Security-Policy" in headers
    
    async def test_cors_headers(self, test_client: httpx.AsyncClient):
        """Test CORS headers."""
        response = await test_client.options(
            "/api/v1/auth/login",
            headers={"Origin": "http://localhost:3000"}
        )
        
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers


class TestHealth:
    """Test health check endpoints."""
    
    async def test_basic_health(self, test_client: httpx.AsyncClient):
        """Test basic health endpoint."""
        response = await test_client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "healthy"
        assert "timestamp" in data
    
    async def test_readiness_check(self, test_client: httpx.AsyncClient):
        """Test readiness check."""
        response = await test_client.get("/health/ready")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "ready"
        assert data["checks"]["redis"] == "healthy"