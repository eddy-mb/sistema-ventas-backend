from sqlmodel import SQLModel


class LoginData(SQLModel):
    email: str
    password: str


# Esquemas Pydantic para API
class RoleRead(SQLModel):
    """Esquema para leer roles."""

    id: int
    name: str
    description: str | None = None


class RoleCreate(SQLModel):
    """Esquema para crear roles."""

    name: str
    description: str | None = None


class RoleUpdate(SQLModel):
    """Esquema para actualizar roles."""

    name: str | None = None
    description: str | None = None


class PermissionRead(SQLModel):
    """Esquema para leer permisos."""

    id: int
    code: str
    name: str
    description: str | None = None
    module: str
