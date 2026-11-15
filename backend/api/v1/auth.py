"""Authentication and user management API routes."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...database import get_db
from ...models.user import User
from ...models.audit import AuditLog
from ...models.base import utc_now
from ...schemas.auth import (
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
    UserRoleUpdate,
)
from ...security.dependencies import get_current_user, require_role
from ...services.auth_service import (
    authenticate_user,
    create_access_token,
    create_user,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"description": "Username already exists"}},
)
def register(
    payload: UserRegisterRequest,
    db: Session = Depends(get_db),
) -> UserResponse:
    """Register a new user account."""
    try:
        user = create_user(
            db,
            username=payload.username,
            password=payload.password,
            email=payload.email,
            role="viewer",
        )
        from ...services.audit_service import record_audit_log
        record_audit_log(
            db,
            actor="system/registration",
            action="REGISTER_USER",
            resource_type="user",
            resource_id=user.id,
            details={"username": user.username, "role": user.role},
        )
        return UserResponse.model_validate(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{payload.username}' is already taken",
        )


@router.post(
    "/login",
    response_model=TokenResponse,
    responses={401: {"description": "Invalid credentials"}},
)
def login(
    payload: UserLoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate with username and password to obtain a JWT Bearer token."""
    user = authenticate_user(db, payload.username, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.username, "role": user.role, "uid": user.id}
    )
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        username=user.username,
        user_id=user.id,
        role=user.role,
    )


@router.get(
    "/me",
    response_model=UserResponse,
)
def get_current_user_profile(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Return profile of the currently authenticated user."""
    return UserResponse.model_validate(current_user)


@router.get(
    "/users",
    response_model=list[UserResponse],
    dependencies=[Depends(require_role(["admin"]))],
)
def list_users(
    db: Session = Depends(get_db),
) -> list[UserResponse]:
    """List all registered users (Administrator only)."""
    users = list(db.execute(select(User).order_by(User.created_at.desc())).scalars().all())
    return [UserResponse.model_validate(u) for u in users]


@router.patch("/users/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: str,
    payload: UserRoleUpdate,
    current_user: User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Change a role as an administrator while preserving an active administrator."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    old_role = user.role
    if old_role == "admin" and payload.role != "admin" and user.account_status == "active":
        active_admins = db.scalar(
            select(func.count()).select_from(User).where(
                User.role == "admin", User.account_status == "active"
            )
        )
        if active_admins <= 1:
            raise HTTPException(status_code=409, detail="Cannot demote the final active administrator")
    if payload.role != old_role:
        user.role = payload.role
        db.add(AuditLog(
            actor=current_user.username,
            action="CHANGE_USER_ROLE",
            resource_type="user",
            resource_id=user.id,
            timestamp=utc_now(),
            details={"old_role": old_role, "new_role": payload.role},
        ))
        db.commit()
        db.refresh(user)
    return UserResponse.model_validate(user)

