from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


class AuditableModel(SQLModel):
    """Modelo base que incluye campos de auditoría estándar"""

    estado_audit: bool = Field(default=True, index=True)
    usuario_creacion: str | None = Field(default=None)
    fecha_creacion: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    usuario_modificacion: str | None = Field(default=None)
    fecha_modificacion: datetime | None = Field(default=None)


class IdentifiableModel(SQLModel):
    """Modelo base que incluye un ID único"""

    id: int | None = Field(default=None, primary_key=True)


class BaseModel(IdentifiableModel, AuditableModel):
    """Modelo base combinado con ID y campos de auditoría"""

    pass
