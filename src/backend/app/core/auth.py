"""
JWT Authentication and Authorization Module
Implements secure JWT-based authentication for API endpoints
"""

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# Simplified imports for compatibility
try:
    from app.core.unified_config import get_settings

    settings = get_settings()
    JWT_SECRET = settings.security.jwt_secret
except:
    # Fallback for when config isn't available
    settings = None
    JWT_SECRET = "fallback-jwt-secret-change-in-prod"

logger = logging.getLogger(__name__)

# Simplified JWT Security without passlib dependency
security = HTTPBearer()


class AuthenticationError(Exception):
    """Custom authentication error"""

    pass


class AuthorizationError(Exception):
    """Custom authorization error"""

    pass


class JWTManager:
    """JWT token management"""

    def __init__(self):
        # Use fallback if settings is not a proper object
        if settings and hasattr(settings, "security") and hasattr(settings.security, "jwt_secret"):
            self.secret_key = settings.security.jwt_secret
        else:
            self.secret_key = JWT_SECRET

        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30
        self.refresh_token_expire_days = 7

    def create_access_token(self, data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        to_encode.update({"exp": expire, "type": "access"})

        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        to_encode.update({"exp": expire, "type": "refresh"})

        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid token")


class AuthService:
    """Authentication service"""

    def __init__(self):
        self.jwt_manager = JWTManager()
        # In production, this would connect to a proper user database
        self.users_db = {
            "admin": {
                "username": "admin",
                "email": "admin@obsera.com",
                "hashed_password": self.hash_password("admin123!"),
                "roles": ["admin", "enterprise", "enterprise-admin"],
                "is_active": True,
                "subscription": "enterprise",
                "license_type": "enterprise",
            },
            "user@demo.com": {
                "username": "user@demo.com",
                "email": "user@demo.com",
                "hashed_password": self.hash_password("password"),
                "roles": ["individual", "user"],
                "is_active": True,
                "subscription": "individual",
                "license_type": "standard",
            },
            "analyst": {
                "username": "analyst",
                "email": "analyst@obsera.com",
                "hashed_password": self.hash_password("analyst123!"),
                "roles": ["analyst", "user"],
                "is_active": True,
                "subscription": "professional",
                "license_type": "professional",
            },
            "owner@obsera.com": {
                "username": "owner@obsera.com",
                "email": "owner@obsera.com",
                "hashed_password": self.hash_password("owner123!"),
                "roles": ["owner", "system-owner", "super-admin", "global-admin"],
                "is_active": True,
                "subscription": "owner",
                "license_type": "owner",
            },
            "api_user": {
                "username": "api_user",
                "email": "api@obsera.com",
                "hashed_password": self.hash_password("apikey123!"),
                "roles": ["api_access"],
                "is_active": True,
                "subscription": "api",
                "license_type": "api",
            },
        }

    def hash_password(self, password: str) -> str:
        """Hash password using simple hash (fallback)"""
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash (simplified)"""
        return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user credentials"""
        user = self.users_db.get(username)
        if not user:
            return None

        if not self.verify_password(password, user["hashed_password"]):
            return None

        if not user.get("is_active", False):
            return None

        return user

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username"""
        return self.users_db.get(username)

    def create_user_tokens(self, user: Dict[str, Any]) -> Dict[str, str]:
        """Create access and refresh tokens for user"""
        token_data = {
            "sub": user["username"],
            "email": user["email"],
            "roles": user["roles"],
            "subscription": user.get("subscription", "standard"),
            "license_type": user.get("license_type", "standard"),
        }

        access_token = self.jwt_manager.create_access_token(token_data)
        refresh_token = self.jwt_manager.create_refresh_token(token_data)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }


# Global auth service instance
auth_service = AuthService()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
) -> Dict[str, Any]:
    """Get current authenticated user from JWT token, with development mode bypass"""

    # Development mode bypass - return default admin user if no credentials provided
    try:
        # Check if we're in development environment (multiple ways to ensure it works)
        is_dev = False
        if settings and hasattr(settings, 'is_development'):
            try:
                is_dev = settings.is_development()
            except:
                is_dev = getattr(settings, 'app_environment', 'development') == 'development'
        elif settings and hasattr(settings, 'app_environment'):
            is_dev = settings.app_environment == 'development'
        else:
            # Fallback to environment variable
            import os
            is_dev = os.getenv('APP_ENVIRONMENT', 'development') == 'development'
        
        if is_dev and not credentials:
            logger.info("🔓 Development mode: Providing default admin user for unauthenticated request")
            return {
                "username": "dev_admin",
                "email": "dev@obsera.com",
                "roles": ["admin", "enterprise", "enterprise-admin", "analyst", "api_access", "user"],
                "is_active": True,
                "subscription": "enterprise",
                "license_type": "enterprise"
            }
    except Exception as e:
        logger.error(f"Error in development mode check: {e}")
        # Continue with normal authentication flow

    # If no credentials and not in development mode, require authentication
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Extract token from Authorization header
        token = credentials.credentials

        # Verify and decode token
        payload = auth_service.jwt_manager.verify_token(token)

        # Get username from token
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception

        # Get user from database
        user = auth_service.get_user_by_username(username)
        if user is None:
            raise credentials_exception

        return user

    except AuthenticationError:
        raise credentials_exception
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise credentials_exception


async def require_roles(required_roles: list) -> Dict[str, Any]:
    """Dependency to require specific roles"""

    def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_roles = current_user.get("roles", [])

        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {required_roles}",
            )

        return current_user

    return role_checker


# Convenience functions for common role requirements
async def require_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Require admin role"""
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return current_user


async def require_analyst(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Require analyst role or higher"""
    user_roles = current_user.get("roles", [])
    if not any(role in user_roles for role in ["admin", "analyst"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Analyst role or higher required"
        )
    return current_user


async def require_api_access(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Require API access"""
    user_roles = current_user.get("roles", [])
    if not any(role in user_roles for role in ["admin", "analyst", "api_access"]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="API access required")
    return current_user


# Optional authentication for public endpoints that can benefit from user context
async def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
) -> Optional[Dict[str, Any]]:
    """Get current user if token provided, None otherwise"""
    if not credentials:
        return None

    try:
        token = credentials.credentials
        payload = auth_service.jwt_manager.verify_token(token)
        username = payload.get("sub")

        if username:
            return auth_service.get_user_by_username(username)
    except:
        pass  # Invalid token, return None

    return None


# Alias for compatibility with the import expectations
async def get_current_admin_user(
    current_user: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    """Get current admin user (alias for require_admin)"""
    return current_user
