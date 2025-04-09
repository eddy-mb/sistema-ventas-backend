from datetime import datetime
from typing import TYPE_CHECKING

from pydantic import EmailStr
from sqlmodel import Field, Relationship, SQLModel

if TYPE_CHECKING:
    from app.models.auth.role_model import UserRole

from app.core.enums import UserStatus
from app.models.auditoria.base_model import BaseModel


class UserBase(SQLModel):
    """Modelo base para usuarios del sistema."""

    username: str = Field(max_length=50, index=True)
    email: EmailStr = Field(max_length=100, index=True)
    full_name: str = Field(max_length=100)
    is_active: bool = Field(default=True)
    status: UserStatus = Field(default=UserStatus.ACTIVE)
    failed_login_attempts: int = Field(default=0)


class User(UserBase, BaseModel, table=True):
    """Modelo de usuario para la base de datos."""

    __tablename__ = "usuarios"
    __table_args__ = {"schema": "auth"}

    hashed_password: str = Field(max_length=255)
    is_superuser: bool = Field(default=False)
    last_login: datetime | None = Field(default=None)
    password_change_date: datetime | None = Field(default=None)

    # Relationships
    roles: list["UserRole"] = Relationship(back_populates="user")


class UserRead(UserBase):
    """Esquema para leer información de usuario."""

    id: int
    last_login: datetime | None = None


class UserCreate(UserBase):
    """Esquema para crear usuarios."""

    password: str = Field(min_length=8)


class UserUpdate(SQLModel):
    """Esquema para actualizar usuarios."""

    username: str | None = None
    email: EmailStr | None = None
    full_name: str | None = None
    is_active: bool | None = None
    status: UserStatus | None = None
