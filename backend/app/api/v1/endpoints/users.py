"""
SecureSight - User Management Endpoints
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog
import uuid

from app.core.database import get_db
from app.core.security import get_current_user, get_password_hash, require_roles, TokenData
from app.models.user import User
from app.models.api_key import ApiKey

logger = structlog.get_logger()
router = APIRouter()


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str]
    is_active: bool
    roles: list[str]
    
    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    roles: Optional[str] = None
    is_active: Optional[bool] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current user profile"""
    result = await db.execute(select(User).where(User.id == current_user.sub))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(
        id=str(user.id),
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        is_active=user.is_active,
        roles=user.get_roles(),
    )


@router.patch("/me", response_model=UserResponse)
async def update_current_user_profile(
    profile_update: ProfileUpdate,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update current user profile"""
    result = await db.execute(select(User).where(User.id == current_user.sub))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if profile_update.full_name is not None:
        user.full_name = profile_update.full_name
    if profile_update.email is not None:
        # Check if email already exists
        existing = await db.execute(
            select(User).where(User.email == profile_update.email, User.id != current_user.sub)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        user.email = profile_update.email
    
    await db.flush()
    
    logger.info("Profile updated", user_id=current_user.sub)
    
    return UserResponse(
        id=str(user.id),
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        is_active=user.is_active,
        roles=user.get_roles(),
    )


@router.post("/me/change-password")
async def change_password(
    password_change: PasswordChange,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change current user password"""
    from app.core.security import verify_password
    
    result = await db.execute(select(User).where(User.id == current_user.sub))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not verify_password(password_change.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    user.hashed_password = get_password_hash(password_change.new_password)
    await db.flush()
    
    logger.info("Password changed", user_id=current_user.sub)
    
    return {"status": "success", "message": "Password changed successfully"}


# API Key Models
class ApiKeyCreate(BaseModel):
    name: str
    description: Optional[str] = None


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    key_prefix: str
    is_active: bool
    last_used_at: Optional[datetime] = None
    created_at: datetime
    expires_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class ApiKeyCreatedResponse(ApiKeyResponse):
    """Response when creating a new API key - includes the full key (only shown once)"""
    key: str


# API Key Endpoints
@router.get("/me/api-keys", response_model=List[ApiKeyResponse])
async def list_api_keys(
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all API keys for current user"""
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.user_id == current_user.sub)
        .order_by(ApiKey.created_at.desc())
    )
    api_keys = result.scalars().all()
    
    return [
        ApiKeyResponse(
            id=str(key.id),
            name=key.name,
            description=key.description,
            key_prefix=key.key_prefix,
            is_active=key.is_active,
            last_used_at=key.last_used_at,
            created_at=key.created_at,
            expires_at=key.expires_at,
        )
        for key in api_keys
    ]


@router.post("/me/api-keys", response_model=ApiKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    api_key_create: ApiKeyCreate,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new API key for current user
    
    The full API key is only returned once at creation time.
    Store it securely as it cannot be retrieved again.
    """
    # Create the API key
    api_key, raw_key = ApiKey.create_key(
        name=api_key_create.name,
        user_id=uuid.UUID(current_user.sub),
        description=api_key_create.description,
    )
    
    db.add(api_key)
    await db.flush()
    
    logger.info("API key created", user_id=current_user.sub, key_id=str(api_key.id))
    
    return ApiKeyCreatedResponse(
        id=str(api_key.id),
        name=api_key.name,
        description=api_key.description,
        key_prefix=api_key.key_prefix,
        is_active=api_key.is_active,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
        key=raw_key,  # Only returned at creation time
    )


@router.delete("/me/api-keys/{key_id}")
async def delete_api_key(
    key_id: str,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete an API key"""
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == key_id,
            ApiKey.user_id == current_user.sub
        )
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    await db.delete(api_key)
    
    logger.info("API key deleted", user_id=current_user.sub, key_id=key_id)
    
    return {"status": "deleted", "key_id": key_id}


@router.post("/me/api-keys/{key_id}/revoke")
async def revoke_api_key(
    key_id: str,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an API key (deactivate without deleting)"""
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == key_id,
            ApiKey.user_id == current_user.sub
        )
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    api_key.is_active = False
    await db.flush()
    
    logger.info("API key revoked", user_id=current_user.sub, key_id=key_id)
    
    return {"status": "revoked", "key_id": key_id}


@router.get("/", response_model=List[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    current_user: TokenData = Depends(require_roles(["admin"])),
    db: AsyncSession = Depends(get_db),
):
    """List all users (admin only)"""
    result = await db.execute(
        select(User).offset(skip).limit(limit)
    )
    users = result.scalars().all()
    
    return [
        UserResponse(
            id=str(u.id),
            email=u.email,
            username=u.username,
            full_name=u.full_name,
            is_active=u.is_active,
            roles=u.get_roles(),
        )
        for u in users
    ]


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get user by ID"""
    # Users can view themselves, admins can view anyone
    if user_id != current_user.sub and "admin" not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized"
        )
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(
        id=str(user.id),
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        is_active=user.is_active,
        roles=user.get_roles(),
    )


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    current_user: TokenData = Depends(require_roles(["admin"])),
    db: AsyncSession = Depends(get_db),
):
    """Update user (admin only)"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user_update.full_name is not None:
        user.full_name = user_update.full_name
    if user_update.roles is not None:
        user.roles = user_update.roles
    if user_update.is_active is not None:
        user.is_active = user_update.is_active
    
    await db.flush()
    
    logger.info("User updated", user_id=user_id, by=current_user.sub)
    
    return UserResponse(
        id=str(user.id),
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        is_active=user.is_active,
        roles=user.get_roles(),
    )


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    current_user: TokenData = Depends(require_roles(["admin"])),
    db: AsyncSession = Depends(get_db),
):
    """Delete user (admin only)"""
    if user_id == current_user.sub:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete yourself"
        )
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    await db.delete(user)
    
    logger.info("User deleted", user_id=user_id, by=current_user.sub)
    
    return {"status": "deleted", "user_id": user_id}
