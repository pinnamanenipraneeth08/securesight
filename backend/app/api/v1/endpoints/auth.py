"""
SecureSight - Authentication Endpoints
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from io import BytesIO
import base64

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog
import pyotp
import qrcode

from app.core.database import get_db
from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    get_current_user_optional,
    Token,
    TokenData,
)
from app.core.config import settings
from app.models.user import User

logger = structlog.get_logger()
router = APIRouter()


class UserCreate(BaseModel):
    """User registration request"""
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None
    role: Optional[str] = None  # Admin can specify role for new users


class UserResponse(BaseModel):
    """User response (without password)"""
    id: str
    email: str
    username: str
    full_name: Optional[str]
    is_active: bool
    roles: list[str]
    
    class Config:
        from_attributes = True


class LoginResponse(BaseModel):
    """Login response with tokens"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class RefreshRequest(BaseModel):
    """Refresh token request"""
    refresh_token: str


class MFASetupResponse(BaseModel):
    """MFA setup response with QR code"""
    secret: str
    qr_code: str  # Base64 encoded QR code image
    provisioning_uri: str


class MFAVerifyRequest(BaseModel):
    """MFA verification request"""
    code: str


class MFALoginVerifyRequest(BaseModel):
    """MFA verification during login"""
    mfa_token: str
    code: str


class MFALoginResponse(BaseModel):
    """Response when MFA is required"""
    mfa_required: bool = True
    mfa_token: str  # Temporary token for MFA verification
    message: str = "MFA verification required"


@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[TokenData] = Depends(get_current_user_optional),
):
    """
    Register a new user account.
    
    - First user registered becomes admin (no authentication required)
    - Subsequent users can only be created by an admin
    - Admin can specify role: 'admin', 'analyst', 'viewer'
    """
    # Check if this is the first user
    result = await db.execute(select(User))
    is_first_user = result.first() is None
    
    # If not first user, require admin authentication
    if not is_first_user:
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Only admins can create new users.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if "admin" not in current_user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators can create new users"
            )
    
    # Check if email exists
    result = await db.execute(
        select(User).where(User.email == user_data.email)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Check if username exists
    result = await db.execute(
        select(User).where(User.username == user_data.username)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    # Determine role for new user
    valid_roles = ["admin", "analyst", "viewer"]
    if is_first_user:
        user_role = "admin"
    elif user_data.role and user_data.role in valid_roles:
        user_role = user_data.role  # Admin specified a role
    else:
        user_role = "viewer"  # Default role
    
    # Create user
    user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        is_active=True,
        is_verified=True,  # Admin-created users are verified
        roles=user_role,
    )
    
    db.add(user)
    await db.flush()
    
    logger.info("User registered", username=user.username, role=user_role, created_by=current_user.sub if current_user else "self")
    
    return UserResponse(
        id=str(user.id),
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        is_active=user.is_active,
        roles=user.get_roles(),
    )


@router.post("/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """
    Login with username/email and password.
    
    If MFA is enabled, returns a temporary MFA token.
    Otherwise returns access and refresh tokens.
    """
    # Find user by username or email
    result = await db.execute(
        select(User).where(
            (User.username == form_data.username) | (User.email == form_data.username)
        )
    )
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated"
        )
    
    # Check if MFA is enabled
    if user.mfa_enabled and user.mfa_secret:
        # Return MFA token - a short-lived token that requires MFA verification
        mfa_token = create_access_token(
            subject=str(user.id),
            roles=[],  # No roles until MFA verified
            expires_delta=timedelta(minutes=5),  # 5 minute expiry
            additional_claims={"mfa_pending": True}
        )
        logger.info("MFA required for login", username=user.username)
        return MFALoginResponse(
            mfa_required=True,
            mfa_token=mfa_token,
            message="MFA verification required"
        )
    
    # No MFA - proceed with normal login
    user.last_login = datetime.utcnow()
    
    # Create tokens
    access_token = create_access_token(
        subject=str(user.id),
        roles=user.get_roles(),
    )
    refresh_token = create_refresh_token(subject=str(user.id))
    
    logger.info("User logged in", username=user.username)
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(
            id=str(user.id),
            email=user.email,
            username=user.username,
            full_name=user.full_name,
            is_active=user.is_active,
            roles=user.get_roles(),
        ),
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    request: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Refresh access token using refresh token.
    """
    token_data = decode_token(request.refresh_token)
    
    if not token_data or token_data.type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Get user
    result = await db.execute(
        select(User).where(User.id == token_data.sub)
    )
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Create new tokens
    access_token = create_access_token(
        subject=str(user.id),
        roles=user.get_roles(),
    )
    new_refresh_token = create_refresh_token(subject=str(user.id))
    
    return Token(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get current user information.
    """
    result = await db.execute(
        select(User).where(User.id == current_user.sub)
    )
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


# ==================== MFA Endpoints ====================

@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Setup MFA for the current user.
    
    Returns a secret and QR code for authenticator apps.
    User must verify with /mfa/verify-setup to complete setup.
    """
    result = await db.execute(
        select(User).where(User.id == current_user.sub)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled. Disable it first to reconfigure."
        )
    
    # Generate a new TOTP secret
    secret = pyotp.random_base32()
    
    # Store secret (not enabled until verified)
    user.mfa_secret = secret
    await db.commit()
    
    # Create provisioning URI for authenticator apps
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="SecureSight"
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    logger.info("MFA setup initiated", username=user.username)
    
    return MFASetupResponse(
        secret=secret,
        qr_code=f"data:image/png;base64,{qr_base64}",
        provisioning_uri=provisioning_uri,
    )


@router.post("/mfa/verify-setup")
async def verify_mfa_setup(
    request: MFAVerifyRequest,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Verify MFA setup by providing a valid TOTP code.
    
    This completes the MFA setup process.
    """
    result = await db.execute(
        select(User).where(User.id == current_user.sub)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup not initiated. Call /mfa/setup first."
        )
    
    if user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled."
        )
    
    # Verify the TOTP code
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(request.code, valid_window=1):  # Allow 1 window tolerance
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code. Please try again."
        )
    
    # Enable MFA
    user.mfa_enabled = True
    await db.commit()
    
    logger.info("MFA enabled", username=user.username)
    
    return {"message": "MFA successfully enabled", "mfa_enabled": True}


@router.post("/mfa/verify", response_model=LoginResponse)
async def verify_mfa_login(
    request: MFALoginVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Verify MFA code during login.
    
    Takes the temporary MFA token and TOTP code, returns full auth tokens.
    """
    # Decode the MFA token
    token_data = decode_token(request.mfa_token)
    
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA token"
        )
    
    # Get user
    result = await db.execute(
        select(User).where(User.id == token_data.sub)
    )
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled for this user"
        )
    
    # Verify the TOTP code
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(request.code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code"
        )
    
    # Update last login
    user.last_login = datetime.utcnow()
    await db.commit()
    
    # Create full auth tokens
    access_token = create_access_token(
        subject=str(user.id),
        roles=user.get_roles(),
    )
    refresh_token = create_refresh_token(subject=str(user.id))
    
    logger.info("MFA verified, user logged in", username=user.username)
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(
            id=str(user.id),
            email=user.email,
            username=user.username,
            full_name=user.full_name,
            is_active=user.is_active,
            roles=user.get_roles(),
        ),
    )


@router.post("/mfa/disable")
async def disable_mfa(
    request: MFAVerifyRequest,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Disable MFA for the current user.
    
    Requires a valid TOTP code to confirm.
    """
    result = await db.execute(
        select(User).where(User.id == current_user.sub)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled"
        )
    
    # Verify the TOTP code
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(request.code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )
    
    # Disable MFA
    user.mfa_enabled = False
    user.mfa_secret = None
    await db.commit()
    
    logger.info("MFA disabled", username=user.username)
    
    return {"message": "MFA successfully disabled", "mfa_enabled": False}


@router.get("/mfa/status")
async def get_mfa_status(
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get MFA status for the current user.
    """
    result = await db.execute(
        select(User).where(User.id == current_user.sub)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {
        "mfa_enabled": user.mfa_enabled,
        "mfa_configured": user.mfa_secret is not None,
    }
