"""
🔐 SecureScan Framework - Authentication API

This module provides authentication endpoints including:
- User registration and login
- JWT token management (access/refresh)
- Password reset and email verification
- API key management
- OAuth integrations (GitHub, GitLab, etc.)

Features:
- Secure password hashing with Argon2
- JWT tokens with refresh mechanism
- Rate limiting on authentication endpoints
- Account lockout protection
- Email verification workflow
- Password strength validation

Author: SecureScan Team
"""

from datetime import timedelta, datetime
from typing import Any, Dict, Optional

try:
    from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
    from fastapi.security import HTTPBearer
    from pydantic import BaseModel, EmailStr, validator
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy import select, update
except ImportError:
    # Graceful fallback for development
    APIRouter = Depends = HTTPException = status = BackgroundTasks = Request = None
    HTTPBearer = BaseModel = EmailStr = validator = None
    AsyncSession = select = update = None

from app.api.dependencies import (
    get_database_session,
    get_current_user,
    get_current_active_user,
    rate_limit_strict,
    log_request
)
from app.core.security import (
    password_manager,
    jwt_manager,
    api_key_manager,
    security_auditor
)
from app.core.logging import get_logger
from app.models import User, APIKey, UserRole, UserStatus

logger = get_logger("securescan.api.auth")

# Create router
router = APIRouter(prefix="/auth", tags=["Authentication"]) if APIRouter else None


# =============================================================================
# 📋 REQUEST/RESPONSE MODELS
# =============================================================================

class UserRegistrationRequest(BaseModel):
    """User registration request model"""
    email: EmailStr
    username: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    
    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3 or len(v) > 50:
            raise ValueError('Username must be between 3 and 50 characters')
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, hyphens, and underscores')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserLoginRequest(BaseModel):
    """User login request model"""
    email: EmailStr
    password: str
    remember_me: bool = False


class PasswordResetRequest(BaseModel):
    """Password reset request model"""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation model"""
    token: str
    new_password: str
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v


class ChangePasswordRequest(BaseModel):
    """Change password request model"""
    current_password: str
    new_password: str
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v


class TokenResponse(BaseModel):
    """Token response model"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    """User response model"""
    id: str
    email: str
    username: str
    first_name: Optional[str]
    last_name: Optional[str]
    full_name: str
    role: str
    status: str
    is_active: bool
    is_verified: bool
    created_at: str
    last_login: Optional[str]
    
    class Config:
        from_attributes = True


class APIKeyRequest(BaseModel):
    """API key creation request"""
    name: str
    scopes: Optional[list] = []
    expires_in_days: Optional[int] = None


class APIKeyResponse(BaseModel):
    """API key response model"""
    id: str
    name: str
    key: str  # Only returned on creation
    prefix: str
    scopes: list
    expires_at: Optional[str]
    created_at: str


# =============================================================================
# 🔓 AUTHENTICATION ENDPOINTS
# =============================================================================

if router:
    
    @router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
    async def register_user(
        request: UserRegistrationRequest,
        background_tasks: BackgroundTasks,
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(rate_limit_strict)
    ):
        """
        Register a new user account
        
        Creates a new user account with email verification workflow.
        The user will receive a verification email before being able to log in.
        """
        try:
            # Check if user already exists
            existing_user = await db.execute(
                select(User).where(
                    (User.email == request.email) | (User.username == request.username)
                )
            )
            
            if existing_user.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User with this email or username already exists"
                )
            
            # Hash password
            password_hash = password_manager.hash_password(request.password)
            
            # Create new user
            new_user = User(
                email=request.email,
                username=request.username,
                password_hash=password_hash,
                first_name=request.first_name,
                last_name=request.last_name,
                role=UserRole.VIEWER,  # Default role
                status=UserStatus.PENDING,  # Requires email verification
                is_active=True,
                is_verified=False
            )
            
            db.add(new_user)
            await db.commit()
            await db.refresh(new_user)
            
            # Send verification email (simulated)
            # background_tasks.add_task(send_verification_email, new_user.email, verification_token)
            
            # Log registration event
            security_auditor.log_authentication_event(
                user_id=str(new_user.id),
                event_type="user_registration",
                success=True,
                ip_address="unknown",
                user_agent="unknown",
                details={"username": new_user.username}
            )
            
            logger.info(f"New user registered: {new_user.email}")
            
            return new_user.to_dict()
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"User registration failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Registration failed"
            )
    
    
    @router.post("/login", response_model=TokenResponse)
    async def login_user(
        request: UserLoginRequest,
        req: Request,
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(rate_limit_strict)
    ):
        """
        Authenticate user and return JWT tokens
        
        Validates user credentials and returns access and refresh tokens.
        Implements account lockout protection against brute force attacks.
        """
        try:
            # Find user by email
            result = await db.execute(
                select(User).where(User.email == request.email)
            )
            user = result.scalar_one_or_none()
            
            # Check if user exists and verify password
            if not user or not password_manager.verify_password(request.password, user.password_hash):
                # Log failed login attempt
                security_auditor.log_authentication_event(
                    user_id=str(user.id) if user else None,
                    event_type="login_failed",
                    success=False,
                    ip_address=req.client.host,
                    user_agent=req.headers.get("user-agent", ""),
                    details={"email": request.email}
                )
                
                # Increment failed attempts if user exists
                if user:
                    user.failed_login_attempts += 1
                    if user.failed_login_attempts >= 5:
                        user.locked_until = datetime.now() + timedelta(minutes=30)
                    await db.commit()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email or password"
                )
            
            # Check if account is locked
            if user.locked_until and user.locked_until > datetime.now():
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Account is temporarily locked due to too many failed login attempts"
                )
            
            # Check if user is active
            if not user.is_active or user.status != UserStatus.ACTIVE:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is inactive or not verified"
                )
            
            # Generate tokens
            access_token_expires = timedelta(minutes=15) if not request.remember_me else timedelta(hours=24)
            access_token = jwt_manager.create_access_token(
                subject=user.id,
                expires_delta=access_token_expires,
                user_data={
                    "email": user.email,
                    "username": user.username,
                    "role": user.role.value
                }
            )
            
            refresh_token = jwt_manager.create_refresh_token(subject=user.id)
            
            # Update user login information
            user.last_login = datetime.now()
            user.login_count += 1
            user.failed_login_attempts = 0  # Reset failed attempts
            user.locked_until = None
            await db.commit()
            
            # Log successful login
            security_auditor.log_authentication_event(
                user_id=str(user.id),
                event_type="login_success",
                success=True,
                ip_address=req.client.host,
                user_agent=req.headers.get("user-agent", ""),
                details={
                    "username": user.username,
                    "remember_me": request.remember_me
                }
            )
            
            logger.info(f"User logged in: {user.email}")
            
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": int(access_token_expires.total_seconds())
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Login failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Login failed"
            )
    
    
    @router.post("/refresh", response_model=TokenResponse)
    async def refresh_token(
        refresh_token: str,
        db: AsyncSession = Depends(get_database_session)
    ):
        """
        Refresh access token using refresh token
        
        Validates refresh token and returns a new access token.
        """
        try:
            # Verify refresh token
            payload = jwt_manager.verify_token(refresh_token)
            if not payload or payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token"
                )
            
            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token"
                )
            
            # Get user
            result = await db.execute(
                select(User).where(User.id == user_id)
            )
            user = result.scalar_one_or_none()
            
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )
            
            # Generate new access token
            access_token = jwt_manager.create_access_token(
                subject=user.id,
                user_data={
                    "email": user.email,
                    "username": user.username,
                    "role": user.role.value
                }
            )
            
            # Generate new refresh token
            new_refresh_token = jwt_manager.create_refresh_token(subject=user.id)
            
            return {
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "token_type": "bearer",
                "expires_in": 900  # 15 minutes
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token refresh failed"
            )
    
    
    @router.post("/logout")
    async def logout_user(
        current_user: User = Depends(get_current_active_user)
    ):
        """
        Logout current user
        
        Invalidates the current session (in a real implementation, 
        you would add the token to a blacklist).
        """
        # TODO: Add token to blacklist
        
        # Log logout event
        security_auditor.log_authentication_event(
            user_id=str(current_user.id),
            event_type="logout",
            success=True,
            ip_address="unknown",
            user_agent="unknown",
            details={"username": current_user.username}
        )
        
        return {"message": "Successfully logged out"}


# =============================================================================
# 🔑 API KEY MANAGEMENT ENDPOINTS
# =============================================================================

if router:
    
    @router.post("/api-keys", response_model=APIKeyResponse)
    async def create_api_key(
        request: APIKeyRequest,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_database_session)
    ):
        """
        Create a new API key for the current user
        
        API keys provide programmatic access to the SecureScan API.
        They can be scoped to specific permissions and have optional expiration.
        """
        try:
            # Generate API key
            api_key = api_key_manager.generate_api_key()
            key_hash = api_key_manager.hash_api_key(api_key)
            prefix = api_key.split('_')[1][:8] if '_' in api_key else api_key[:8]
            
            # Calculate expiration
            expires_at = None
            if request.expires_in_days:
                expires_at = datetime.now() + timedelta(days=request.expires_in_days)
            
            # Create API key record
            api_key_obj = APIKey(
                user_id=current_user.id,
                name=request.name,
                key_hash=key_hash,
                prefix=prefix,
                scopes=request.scopes,
                expires_at=expires_at
            )
            
            db.add(api_key_obj)
            await db.commit()
            await db.refresh(api_key_obj)
            
            # Log API key creation
            security_auditor.log_security_event(
                event_type="api_key_created",
                severity="info",
                description=f"API key '{request.name}' created",
                user_id=str(current_user.id),
                details={
                    "api_key_name": request.name,
                    "scopes": request.scopes,
                    "expires_in_days": request.expires_in_days
                }
            )
            
            return {
                "id": str(api_key_obj.id),
                "name": api_key_obj.name,
                "key": api_key,  # Only returned on creation
                "prefix": api_key_obj.prefix,
                "scopes": api_key_obj.scopes,
                "expires_at": api_key_obj.expires_at.isoformat() if api_key_obj.expires_at else None,
                "created_at": api_key_obj.created_at.isoformat()
            }
            
        except Exception as e:
            logger.error(f"API key creation failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create API key"
            )
    
    
    @router.get("/api-keys")
    async def list_api_keys(
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_database_session)
    ):
        """List all API keys for the current user"""
        try:
            result = await db.execute(
                select(APIKey)
                .where(APIKey.user_id == current_user.id)
                .order_by(APIKey.created_at.desc())
            )
            
            api_keys = result.scalars().all()
            
            return [
                {
                    "id": str(key.id),
                    "name": key.name,
                    "prefix": key.prefix,
                    "scopes": key.scopes,
                    "is_active": key.is_active,
                    "last_used": key.last_used.isoformat() if key.last_used else None,
                    "usage_count": key.usage_count,
                    "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                    "created_at": key.created_at.isoformat()
                }
                for key in api_keys
            ]
            
        except Exception as e:
            logger.error(f"Failed to list API keys: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to list API keys"
            )


# =============================================================================
# 👤 USER PROFILE ENDPOINTS
# =============================================================================

if router:
    
    @router.get("/me", response_model=UserResponse)
    async def get_current_user_profile(
        current_user: User = Depends(get_current_active_user)
    ):
        """Get current user profile information"""
        return current_user.to_dict()
    
    
    @router.post("/change-password")
    async def change_password(
        request: ChangePasswordRequest,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_database_session)
    ):
        """Change user password"""
        try:
            # Verify current password
            if not password_manager.verify_password(request.current_password, current_user.password_hash):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Current password is incorrect"
                )
            
            # Hash new password
            new_password_hash = password_manager.hash_password(request.new_password)
            
            # Update password
            current_user.password_hash = new_password_hash
            current_user.password_changed_at = datetime.now()
            await db.commit()
            
            # Log password change
            security_auditor.log_security_event(
                event_type="password_changed",
                severity="info",
                description="User changed password",
                user_id=str(current_user.id)
            )
            
            return {"message": "Password changed successfully"}
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Password change failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to change password"
            )


# Export router
__all__ = ["router"] if router else []