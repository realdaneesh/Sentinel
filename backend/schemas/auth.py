"""Pydantic schemas for authentication and user management."""

from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


UserRole = Literal["admin", "analyst", "viewer"]
AccountStatus = Literal["active", "suspended", "disabled"]


class UserRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=3, max_length=64)
    email: str | None = None
    password: str = Field(..., min_length=8, max_length=128)


class UserRoleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: UserRole


class UserLoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    user_id: str
    role: UserRole


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    email: str | None = None
    role: UserRole
    account_status: AccountStatus
    created_at: datetime

