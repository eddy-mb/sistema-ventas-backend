from typing import TYPE_CHECKING, List, Optional

from sqlmodel import Field, Relationship, SQLModel

if TYPE_CHECKING:
    from app.models.auth.user_model import User

from app.models.auditoria.base_model import BaseModel


class Role(BaseModel, table=True):
    """Modelo para roles del sistema."""

    __tablename__ = "roles"

    name: str = Field(max_length=50, index=True)
    description: Optional[str] = Field(max_length=255, default=None)
    is_system_role: bool = Field(default=False)

    # Relationships
    users: List["UserRole"] = Relationship(back_populates="role")
    permissions: List["RolePermission"] = Relationship(back_populates="role")


class Permission(BaseModel, table=True):
    """Modelo para permisos del sistema."""

    __tablename__ = "permissions"

    code: str = Field(max_length=100, index=True)
    name: str = Field(max_length=100)
    description: Optional[str] = Field(max_length=255, default=None)
    module: str = Field(max_length=50)

    # Relationships
    roles: List["RolePermission"] = Relationship(back_populates="permission")


class UserRole(BaseModel, table=True):
    """Tabla de relación entre usuarios y roles."""

    __tablename__ = "user_roles"

    user_id: int = Field(foreign_key="users.id")
    role_id: int = Field(foreign_key="roles.id")

    # Relationships
    user: "User" = Relationship(back_populates="roles")
    role: Role = Relationship(back_populates="users")


class RolePermission(BaseModel, table=True):
    """Tabla de relación entre roles y permisos."""

    __tablename__ = "role_permissions"

    role_id: int = Field(foreign_key="roles.id")
    permission_id: int = Field(foreign_key="permissions.id")

    # Relationships
    role: Role = Relationship(back_populates="permissions")
    permission: Permission = Relationship(back_populates="role")


# Esquemas Pydantic para API
class RoleRead(SQLModel):
    """Esquema para leer roles."""

    id: int
    name: str
    description: Optional[str] = None


class RoleCreate(SQLModel):
    """Esquema para crear roles."""

    name: str
    description: Optional[str] = None


class RoleUpdate(SQLModel):
    """Esquema para actualizar roles."""

    name: Optional[str] = None
    description: Optional[str] = None


class PermissionRead(SQLModel):
    """Esquema para leer permisos."""

    id: int
    code: str
    name: str
    description: Optional[str] = None
    module: str
