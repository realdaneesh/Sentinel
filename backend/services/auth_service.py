"""Authentication service providing password hashing, JWT management, and user lookups."""

from datetime import datetime, timedelta, timezone
from typing import Any
import bcrypt
import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..logging import logger
from ..models.user import User


def hash_password(password: str) -> str:
    """Hash password using bcrypt with salt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against stored bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    """Generate signed JWT access token."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate signed JWT access token."""
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


def get_user_by_username(db: Session, username: str) -> User | None:
    """Retrieve user record by username."""
    return db.execute(select(User).where(User.username == username)).scalar_one_or_none()


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    """Authenticate credentials and return User if valid and active."""
    user = get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    if user.account_status != "active":
        return None
    return user


def create_user(
    db: Session,
    username: str,
    password: str,
    email: str | None = None,
    role: str = "viewer",
) -> User:
    """Create and persist a new user."""
    password_hash = hash_password(password)
    user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        role=role,
        account_status="active",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
