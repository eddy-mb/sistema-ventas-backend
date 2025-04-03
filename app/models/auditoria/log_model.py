from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel


class LogAuditoria(SQLModel, table=True):
    """Modelo para registrar acciones de auditoría en el sistema."""

    __tablename__ = "log_auditoria"
    __table_args__ = {"schema": "auditoria"}

    id: Optional[int] = Field(default=None, primary_key=True)
    fecha_hora: datetime = Field()
    usuario_id: Optional[int] = Field(default=None, index=True, foreign_key="auth.users.id")
    tipo_accion: str = Field(index=True)
    modulo: str = Field(index=True)
    entidad: str = Field(index=True)
    entidad_id: Optional[int] = Field(default=None, index=True)
    detalles: Optional[str] = Field(default=None)
    ip_origen: str = Field()
    resultado: bool = Field(default=True)
    descripcion: Optional[str] = Field(default=None)
