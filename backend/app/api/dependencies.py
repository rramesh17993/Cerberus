"""
🚀 SecureScan Framework - API Dependencies

This module provides FastAPI dependency injection for:
- Database session management
- User authentication and authorization
- Rate limiting and security checks
- Request validation and pagination
- Error handling and logging

Features:
- Async database session management
- JWT token validation and user extraction
- Role-based access control (RBAC)
- Rate limiting with Redis backend
- Request pagination and filtering
- API key authentication
- Audit logging for all requests

Author: SecureScan Team
"""

from typing import Optional, List, Dict, Any, Generator
from datetime import datetime

try:
    from fastapi import Depends, HTTPException, status, Request, Query
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy import select
except ImportError:
    # Graceful fallback for development
    Depends = HTTPException = status = Request = Query = None
    HTTPBearer = HTTPAuthorizationCredentials = None
    AsyncSession = select = None

from app.core.database import get_db_session, get_db_manager
from app.core.security import jwt_manager, rate_limiter, security_auditor
from app.core.logging import get_logger
from app.models import User, APIKey, UserRole, UserStatus

logger = get_logger("securescan.api.dependencies")


# =============================================================================
# 🗄️ DATABASE DEPENDENCIES
# =============================================================================

async def get_database_session() -> AsyncSession:
    """
    Dependency to get database session
    
    Returns:
        AsyncSession: Database session
    """
    async with get_db_session() as session:
        yield session


# =============================================================================
# 🔐 AUTHENTICATION DEPENDENCIES
# =============================================================================

class AuthenticationError(HTTPException):
    """Custom authentication error"""
    def __init__(self, detail: str = "Authentication failed"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"}
        )


class AuthorizationError(HTTPException):
    """Custom authorization error"""
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )


# Security scheme for JWT tokens
security_scheme = HTTPBearer(auto_error=False) if HTTPBearer else None


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: AsyncSession = Depends(get_database_session)
) -> Optional[User]:
    """
    Get current user from JWT token (optional - returns None if no token)
    
    Args:
        request: FastAPI request object
        credentials: HTTP bearer token
        db: Database session
        
    Returns:
        User object or None if not authenticated
    """
    if not credentials:
        return None
    
    try:
        # Verify JWT token
        payload = jwt_manager.verify_token(credentials.credentials)
        if not payload:
            return None
        
        user_id = payload.get("sub")
        if not user_id:
            return None
        
        # Get user from database
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user or not user.is_active:
            return None
        
        # Log authentication event
        security_auditor.log_authentication_event(
            user_id=str(user.id),
            event_type="token_validation",
            success=True,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent", "")
        )
        
        return user
        
    except Exception as e:
        logger.warning("Token validation failed", error=str(e))
        return None


async def get_current_user(
    user: Optional[User] = Depends(get_current_user_optional)
) -> User:
    """
    Get current user from JWT token (required - raises 401 if no valid token)
    
    Args:
        user: User from optional dependency
        
    Returns:
        User object
        
    Raises:
        AuthenticationError: If no valid token provided
    """
    if not user:
        raise AuthenticationError("Valid authentication token required")
    
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get current active user (ensures user is active and verified)
    
    Args:
        current_user: User from authentication dependency
        
    Returns:
        Active user object
        
    Raises:
        AuthenticationError: If user is inactive or not verified
    """
    if not current_user.is_active:
        raise AuthenticationError("User account is inactive")
    
    if current_user.status != UserStatus.ACTIVE:
        raise AuthenticationError(f"User account status: {current_user.status.value}")
    
    return current_user


# =============================================================================
# 🛡️ AUTHORIZATION DEPENDENCIES
# =============================================================================

def require_role(required_role: UserRole):
    """
    Dependency factory for role-based access control
    
    Args:
        required_role: Minimum required role
        
    Returns:
        Dependency function that checks user role
    """
    async def check_role(current_user: User = Depends(get_current_active_user)) -> User:
        """Check if user has required role"""
        
        # Define role hierarchy (higher index = higher privilege)
        role_hierarchy = [
            UserRole.VIEWER,
            UserRole.DEVELOPER,
            UserRole.MANAGER,
            UserRole.ADMIN
        ]
        
        try:
            user_role_level = role_hierarchy.index(current_user.role)
            required_role_level = role_hierarchy.index(required_role)
            
            if user_role_level < required_role_level:
                security_auditor.log_authorization_event(
                    user_id=str(current_user.id),
                    resource="role_check",
                    action=f"require_{required_role.value}",
                    allowed=False,
                    details={
                        "user_role": current_user.role.value,
                        "required_role": required_role.value
                    }
                )
                raise AuthorizationError(
                    f"Role '{required_role.value}' or higher required. "
                    f"Current role: '{current_user.role.value}'"
                )
            
            return current_user
            
        except ValueError:
            # Role not found in hierarchy
            raise AuthorizationError("Invalid role configuration")
    
    return check_role


# Common role dependencies
require_admin = require_role(UserRole.ADMIN)
require_manager = require_role(UserRole.MANAGER)
require_developer = require_role(UserRole.DEVELOPER)


# =============================================================================
# 🔑 API KEY AUTHENTICATION
# =============================================================================

async def get_api_key_user(
    request: Request,
    db: AsyncSession = Depends(get_database_session)
) -> Optional[User]:
    """
    Authenticate user via API key
    
    Args:
        request: FastAPI request object
        db: Database session
        
    Returns:
        User object if valid API key, None otherwise
    """
    # Check for API key in headers
    api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")
    
    if not api_key or not api_key.startswith("sk_"):
        return None
    
    try:
        # Hash the provided API key
        from app.core.security import api_key_manager
        key_hash = api_key_manager.hash_api_key(api_key)
        
        # Find API key in database
        result = await db.execute(
            select(APIKey)
            .where(APIKey.key_hash == key_hash)
            .where(APIKey.is_active == True)
        )
        
        api_key_obj = result.scalar_one_or_none()
        if not api_key_obj:
            return None
        
        # Check expiration
        if api_key_obj.expires_at and api_key_obj.expires_at < datetime.now():
            return None
        
        # Get associated user
        result = await db.execute(
            select(User).where(User.id == api_key_obj.user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user or not user.is_active:
            return None
        
        # Update usage tracking
        api_key_obj.last_used = datetime.now()
        api_key_obj.usage_count += 1
        await db.commit()
        
        # Log API key usage
        security_auditor.log_authentication_event(
            user_id=str(user.id),
            event_type="api_key_auth",
            success=True,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent", ""),
            details={"api_key_name": api_key_obj.name}
        )
        
        return user
        
    except Exception as e:
        logger.warning("API key authentication failed", error=str(e))
        return None


async def get_user_from_token_or_api_key(
    token_user: Optional[User] = Depends(get_current_user_optional),
    api_key_user: Optional[User] = Depends(get_api_key_user)
) -> Optional[User]:
    """
    Get user from either JWT token or API key
    
    Args:
        token_user: User from JWT token
        api_key_user: User from API key
        
    Returns:
        User object or None
    """
    return token_user or api_key_user


# =============================================================================
# 🚦 RATE LIMITING DEPENDENCIES
# =============================================================================

def create_rate_limit_dependency(
    max_requests: int,
    window_seconds: int = 60,
    key_func: Optional[callable] = None
):
    """
    Create a rate limiting dependency
    
    Args:
        max_requests: Maximum requests allowed
        window_seconds: Time window in seconds
        key_func: Function to generate rate limit key
        
    Returns:
        Rate limiting dependency
    """
    async def rate_limit_check(
        request: Request,
        current_user: Optional[User] = Depends(get_user_from_token_or_api_key)
    ):
        """Check rate limit for request"""
        
        # Generate rate limit key
        if key_func:
            key = key_func(request, current_user)
        elif current_user:
            key = f"user:{current_user.id}"
        else:
            key = f"ip:{request.client.host}"
        
        # Check rate limit
        allowed, current_count, reset_time = await rate_limiter.is_allowed(
            key=key,
            limit=max_requests,
            window_seconds=window_seconds
        )
        
        if not allowed:
            # Log rate limit violation
            if current_user:
                security_auditor.log_security_event(
                    event_type="rate_limit_exceeded",
                    severity="medium",
                    description=f"Rate limit exceeded: {current_count}/{max_requests}",
                    user_id=str(current_user.id),
                    ip_address=request.client.host
                )
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Rate limit exceeded",
                    "limit": max_requests,
                    "window_seconds": window_seconds,
                    "current_count": current_count,
                    "reset_time": reset_time
                },
                headers={
                    "X-RateLimit-Limit": str(max_requests),
                    "X-RateLimit-Remaining": str(max(0, max_requests - current_count)),
                    "X-RateLimit-Reset": str(reset_time)
                }
            )
        
        # Add rate limit headers to response
        request.state.rate_limit_headers = {
            "X-RateLimit-Limit": str(max_requests),
            "X-RateLimit-Remaining": str(max(0, max_requests - current_count)),
            "X-RateLimit-Reset": str(reset_time)
        }
    
    return rate_limit_check


# Common rate limit dependencies
rate_limit_strict = create_rate_limit_dependency(max_requests=100, window_seconds=60)
rate_limit_moderate = create_rate_limit_dependency(max_requests=1000, window_seconds=60)
rate_limit_generous = create_rate_limit_dependency(max_requests=10000, window_seconds=60)


# =============================================================================
# 📄 PAGINATION DEPENDENCIES
# =============================================================================

class PaginationParams:
    """Pagination parameters"""
    
    def __init__(
        self,
        page: int = Query(1, ge=1, description="Page number (starts from 1)"),
        size: int = Query(50, ge=1, le=1000, description="Page size (max 1000)"),
        sort_by: Optional[str] = Query(None, description="Field to sort by"),
        sort_order: str = Query("asc", regex="^(asc|desc)$", description="Sort order")
    ):
        self.page = page
        self.size = size
        self.sort_by = sort_by
        self.sort_order = sort_order
        
        # Calculate offset
        self.offset = (page - 1) * size
        self.limit = size
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "page": self.page,
            "size": self.size,
            "offset": self.offset,
            "limit": self.limit,
            "sort_by": self.sort_by,
            "sort_order": self.sort_order
        }


async def get_pagination_params(
    page: int = Query(1, ge=1, description="Page number (starts from 1)"),
    size: int = Query(50, ge=1, le=1000, description="Page size (max 1000)"),
    sort_by: Optional[str] = Query(None, description="Field to sort by"),
    sort_order: str = Query("asc", regex="^(asc|desc)$", description="Sort order")
) -> PaginationParams:
    """Get pagination parameters from query params"""
    return PaginationParams(page, size, sort_by, sort_order)


# =============================================================================
# 🔍 FILTERING DEPENDENCIES
# =============================================================================

class FilterParams:
    """Common filtering parameters"""
    
    def __init__(
        self,
        search: Optional[str] = Query(None, min_length=1, max_length=255, description="Search term"),
        created_after: Optional[datetime] = Query(None, description="Filter by creation date (after)"),
        created_before: Optional[datetime] = Query(None, description="Filter by creation date (before)"),
        tags: Optional[List[str]] = Query(None, description="Filter by tags"),
    ):
        self.search = search
        self.created_after = created_after
        self.created_before = created_before
        self.tags = tags or []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "search": self.search,
            "created_after": self.created_after.isoformat() if self.created_after else None,
            "created_before": self.created_before.isoformat() if self.created_before else None,
            "tags": self.tags
        }


async def get_filter_params(
    search: Optional[str] = Query(None, min_length=1, max_length=255, description="Search term"),
    created_after: Optional[datetime] = Query(None, description="Filter by creation date (after)"),
    created_before: Optional[datetime] = Query(None, description="Filter by creation date (before)"),
    tags: Optional[List[str]] = Query(None, description="Filter by tags"),
) -> FilterParams:
    """Get filtering parameters from query params"""
    return FilterParams(search, created_after, created_before, tags)


# =============================================================================
# 📊 REQUEST LOGGING DEPENDENCY
# =============================================================================

async def log_request(
    request: Request,
    current_user: Optional[User] = Depends(get_user_from_token_or_api_key)
):
    """
    Log API request for audit trail
    
    Args:
        request: FastAPI request object
        current_user: Current authenticated user (optional)
    """
    try:
        # Extract request information
        method = request.method
        url = str(request.url)
        ip_address = request.client.host
        user_agent = request.headers.get("user-agent", "")
        
        # Log request
        logger.info(
            f"API Request: {method} {url}",
            method=method,
            url=url,
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=str(current_user.id) if current_user else None,
            user_email=current_user.email if current_user else None
        )
        
    except Exception as e:
        logger.error("Failed to log API request", error=str(e))


# Export dependencies
if Depends:
    __all__ = [
        "get_database_session",
        "get_current_user_optional",
        "get_current_user",
        "get_current_active_user",
        "get_api_key_user",
        "get_user_from_token_or_api_key",
        "require_role",
        "require_admin",
        "require_manager",
        "require_developer",
        "create_rate_limit_dependency",
        "rate_limit_strict",
        "rate_limit_moderate",
        "rate_limit_generous",
        "get_pagination_params",
        "get_filter_params",
        "log_request",
        "PaginationParams",
        "FilterParams",
        "AuthenticationError",
        "AuthorizationError"
    ]
else:
    __all__ = [
        "PaginationParams",
        "FilterParams",
        "AuthenticationError",
        "AuthorizationError"
    ]