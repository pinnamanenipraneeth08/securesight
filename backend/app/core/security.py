"""
SecureSight - Security & Authentication
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from pydantic import BaseModel
import structlog

from app.core.config import settings

logger = structlog.get_logger()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for JWT tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

# API Key header for agents
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class TokenData(BaseModel):
    """Token payload data"""
    sub: str
    exp: datetime
    type: str = "access"
    roles: list[str] = []


class Token(BaseModel):
    """Token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)


def create_access_token(
    subject: str,
    roles: Optional[list[str]] = None,
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[dict] = None,
) -> str:
    """Create JWT access token"""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    to_encode = {
        "sub": subject,
        "exp": expire,
        "type": "access",
        "roles": roles or [],
    }
    
    # Add any additional claims
    if additional_claims:
        to_encode.update(additional_claims)
    
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )


def create_refresh_token(subject: str) -> str:
    """Create JWT refresh token"""
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    )
    
    to_encode = {
        "sub": subject,
        "exp": expire,
        "type": "refresh",
    }
    
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )


def decode_token(token: str) -> Optional[TokenData]:
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return TokenData(**payload)
    except JWTError as e:
        logger.warning("Token decode failed", error=str(e))
        return None


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get current user from JWT token"""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token_data = decode_token(token)
    if not token_data or token_data.type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Here you would typically fetch the user from the database
    # For now, we return the token data
    return token_data


async def get_current_user_optional(token: str = Depends(oauth2_scheme)):
    """Get current user if token is provided"""
    if not token:
        return None
    
    token_data = decode_token(token)
    if not token_data or token_data.type != "access":
        return None
    
    return token_data


async def verify_agent_api_key(
    api_key: str = Depends(api_key_header),
):
    """Verify agent API key - supports both static key and database-stored keys"""
    from app.core.database import async_session_factory
    from app.models.api_key import ApiKey
    from sqlalchemy import select
    from datetime import datetime
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )
    
    # First check static API key for backward compatibility
    if api_key == settings.AGENT_API_KEY:
        return api_key
    
    # Check if it's a database-stored API key (starts with sk_)
    if api_key.startswith("sk_"):
        key_hash = ApiKey.verify_key(api_key)
        
        async with async_session_factory() as db:
            result = await db.execute(
                select(ApiKey).where(ApiKey.key_hash == key_hash)
            )
            db_key = result.scalar_one_or_none()
            
            if db_key and db_key.is_valid():
                # Update last used timestamp
                db_key.last_used_at = datetime.utcnow()
                db_key.usage_count = str(int(db_key.usage_count or "0") + 1)
                await db.commit()
                return api_key
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )


def require_roles(required_roles: list[str]):
    """Dependency to check if user has required roles"""
    async def check_roles(user: TokenData = Depends(get_current_user)):
        if not any(role in user.roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user
    return check_roles
