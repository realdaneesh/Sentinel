"""Security dependencies for JWT token authentication and role-based access control."""

from collections.abc import Callable
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy.orm import Session

from ..database import get_db
from ..config import settings
from ..models.user import User
from ..models.producer import EventProducer
from ..services.auth_service import decode_access_token, get_user_by_username
from ..services.producer_service import verify_producer_key

security_bearer = HTTPBearer(auto_error=False)
producer_header = APIKeyHeader(name="X-Sentinel-Producer-Key", auto_error=False)


def require_producer(
    key: str | None = Security(producer_header),
    db: Session = Depends(get_db),
) -> EventProducer:
    """Authorize an event producer separately from user JWT credentials."""
    producer = verify_producer_key(db, key) if key else None
    if producer is None:
        raise HTTPException(status_code=401, detail="Valid producer credential required")
    return producer


def require_producer_source(producer: EventProducer, source: str) -> None:
    if producer.source != source and not (settings.ENVIRONMENT == "testing" and producer.source == "*"):
        raise HTTPException(status_code=403, detail="Producer is not authorized for this source")


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(security_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Validate Bearer JWT access token and return current active User."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (jwt.InvalidTokenError, Exception):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_user_by_username(db, username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.account_status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive or suspended",
        )
    return user


def require_role(allowed_roles: list[str]) -> Callable[[User], User]:
    """Dependency factory enforcing Role-Based Access Control (RBAC).

    Administrators ('admin') always have full permission.
    """
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role == "admin":
            return current_user
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: role '{current_user.role}' is not authorized for this operation. Required: {allowed_roles}",
            )
        return current_user

    return role_checker

