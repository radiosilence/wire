from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field

from wire.config import settings
from wire.crypto import hash_password, verify_password
from wire.models.async_user import AsyncUser, UserExists, UserNotFoundError

router = APIRouter()

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

# JWT settings
JWT_SECRET_KEY = settings.secret_key.get_secret_value()
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
JWT_REFRESH_TOKEN_EXPIRE_DAYS = 30


class TokenResponse(BaseModel):
    """Token response model."""
    
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60


class UserRegisterRequest(BaseModel):
    """User registration request."""
    
    username: str = Field(..., min_length=3, max_length=30, regex="^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    display_name: str | None = Field(None, max_length=100)


class UserLoginRequest(BaseModel):
    """User login request."""
    
    username: str
    password: str


class UserResponse(BaseModel):
    """Public user response."""
    
    username: str
    email: EmailStr
    display_name: str | None
    is_verified: bool
    created_at: datetime
    last_seen: datetime | None


class PasswordResetRequest(BaseModel):
    """Password reset request."""
    
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation."""
    
    token: str
    new_password: str = Field(..., min_length=8, max_length=100)


class ChangePasswordRequest(BaseModel):
    """Change password request."""
    
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=100)


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(data: dict[str, Any]) -> str:
    """Create JWT refresh token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({"exp": expire, "type": "refresh"})
    
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> AsyncUser:
    """Get current authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if username is None or token_type != "access":
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    try:
        user = await AsyncUser.load_by_username(username)
    except UserNotFoundError:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    # Update last seen
    await user.update_last_seen()
    
    return user


async def get_current_active_user(
    current_user: Annotated[AsyncUser, Depends(get_current_user)]
) -> AsyncUser:
    """Get current active user."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


@router.post("/register", response_model=UserResponse)
async def register(request: UserRegisterRequest) -> UserResponse:
    """Register a new user."""
    try:
        # Create user
        user = AsyncUser(
            username=request.username.lower(),
            email=request.email.lower(),
            display_name=request.display_name,
        )
        
        # Set password
        user.set_password(request.password)
        
        # Save user
        await user.save()
        
        # Send verification email (implement this)
        # await send_verification_email(user.email, user.username)
        
        return UserResponse(
            username=user.username,
            email=user.email,
            display_name=user.display_name,
            is_verified=user.is_verified,
            created_at=user.created_at,
            last_seen=user.last_seen,
        )
    
    except UserExists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/token", response_model=TokenResponse)
async def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> TokenResponse:
    """Login and get access token."""
    try:
        # Load user
        user = await AsyncUser.load_by_username(form_data.username.lower())
        
        # Check if account is locked
        if user.is_locked_out():
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Account temporarily locked due to too many failed login attempts"
            )
        
        # Verify password
        if not user.check_password(form_data.password):
            await user.record_failed_login()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is disabled"
            )
        
        # Update login info
        await user.update_login()
        
        # Create tokens
        access_token = create_access_token({"sub": user.username})
        refresh_token = create_refresh_token({"sub": user.username})
        
        # Store refresh token in Redis for validation
        redis_client = request.app.state.redis
        await redis_client.setex(
            f"refresh_token:{user.username}:{refresh_token[-8:]}",
            JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            refresh_token
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    
    except UserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: Request, refresh_token: str) -> TokenResponse:
    """Refresh access token."""
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if username is None or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Verify refresh token exists in Redis
        redis_client = request.app.state.redis
        stored_token = await redis_client.get(f"refresh_token:{username}:{refresh_token[-8:]}")
        
        if not stored_token or stored_token != refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
        
        # Create new access token
        access_token = create_access_token({"sub": username})
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: Annotated[AsyncUser, Depends(get_current_user)],
    refresh_token: str | None = None,
) -> dict[str, str]:
    """Logout user."""
    # Invalidate refresh token if provided
    if refresh_token:
        redis_client = request.app.state.redis
        await redis_client.delete(f"refresh_token:{current_user.username}:{refresh_token[-8:]}")
    
    return {"message": "Successfully logged out"}


@router.post("/password-reset")
async def request_password_reset(
    request: Request,
    reset_request: PasswordResetRequest
) -> dict[str, str]:
    """Request password reset."""
    try:
        user = await AsyncUser.load_by_email(reset_request.email.lower())
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        
        # Store in Redis with expiration
        redis_client = request.app.state.redis
        await redis_client.setex(
            f"password_reset:{reset_token}",
            3600,  # 1 hour expiration
            user.username
        )
        
        # Send reset email (implement this)
        # await send_password_reset_email(user.email, reset_token)
        
        return {"message": "Password reset email sent if account exists"}
    
    except UserNotFoundError:
        # Don't reveal if user exists
        return {"message": "Password reset email sent if account exists"}


@router.post("/password-reset/confirm")
async def confirm_password_reset(
    request: Request,
    reset_confirm: PasswordResetConfirm
) -> dict[str, str]:
    """Confirm password reset."""
    redis_client = request.app.state.redis
    
    # Get username from reset token
    username = await redis_client.get(f"password_reset:{reset_confirm.token}")
    
    if not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )
    
    try:
        # Load user and update password
        user = await AsyncUser.load_by_username(username)
        user.set_password(reset_confirm.new_password)
        await user.save()
        
        # Delete reset token
        await redis_client.delete(f"password_reset:{reset_confirm.token}")
        
        # Invalidate all refresh tokens for security
        pattern = f"refresh_token:{username}:*"
        async for key in redis_client.scan_iter(match=pattern):
            await redis_client.delete(key)
        
        return {"message": "Password successfully reset"}
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/change-password")
async def change_password(
    current_user: Annotated[AsyncUser, Depends(get_current_user)],
    password_change: ChangePasswordRequest,
) -> dict[str, str]:
    """Change user password."""
    # Verify current password
    if not current_user.check_password(password_change.current_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect"
        )
    
    try:
        # Update password
        current_user.set_password(password_change.new_password)
        await current_user.save()
        
        return {"message": "Password successfully changed"}
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: Annotated[AsyncUser, Depends(get_current_user)]
) -> UserResponse:
    """Get current user information."""
    return UserResponse(
        username=current_user.username,
        email=current_user.email,
        display_name=current_user.display_name,
        is_verified=current_user.is_verified,
        created_at=current_user.created_at,
        last_seen=current_user.last_seen,
    )