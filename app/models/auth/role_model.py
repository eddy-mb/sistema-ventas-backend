from typing import TYPE_CHECKING

from sqlmodel import Field, Relationship

if TYPE_CHECKING:
    from app.models.auth.user_model import User

from app.core.enums import Roles
from app.models.auditoria.base_model import BaseModel


class Role(BaseModel, table=True):
    """Modelo para roles del sistema."""

    __tablename__ = "roles"
    __table_args__ = {"schema": "auth"}

    name: Roles = Field(max_length=50, index=True)
    description: str | None = Field(max_length=255, default=None)
    is_system_role: bool = Field(default=False)

    # Relationships
    users: list["UserRole"] = Relationship(back_populates="role")
    permissions: list["RolePermission"] = Relationship(back_populates="role")


class Permission(BaseModel, table=True):
    """Modelo para permisos del sistema."""

    __tablename__ = "permisos"
    __table_args__ = {"schema": "auth"}

    code: str = Field(max_length=100, index=True)
    name: str = Field(max_length=100)
    description: str | None = Field(max_length=255, default=None)
    module: str = Field(max_length=50)

    # Relationships
    roles: list["RolePermission"] = Relationship(back_populates="permission")


class UserRole(BaseModel, table=True):
    """Tabla de relación entre usuarios y roles."""

    __tablename__ = "usuario_roles"
    __table_args__ = {"schema": "auth"}

    user_id: int = Field(foreign_key="auth.usuarios.id")
    role_id: int = Field(foreign_key="auth.roles.id")

    # Relationships
    user: "User" = Relationship(back_populates="roles")
    role: Role = Relationship(back_populates="users")


class RolePermission(BaseModel, table=True):
    """Tabla de relación entre roles y permisos."""

    __tablename__ = "rol_permisos"
    __table_args__ = {"schema": "auth"}

    role_id: int = Field(foreign_key="auth.roles.id")
    permission_id: int = Field(foreign_key="auth.permisos.id")

    # Relationships
    role: Role = Relationship(back_populates="permissions")
    permission: Permission = Relationship(back_populates="roles")
