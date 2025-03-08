from datetime import date, datetime, timezone
from typing import TYPE_CHECKING

from pydantic import EmailStr
from sqlmodel import Field, Relationship, SQLModel

from app.core.enums import EstadoCliente, TipoDocumento

if TYPE_CHECKING:
    from .contacto_emergencia_model import ContactoEmergencia


class ClienteBase(SQLModel):
    nombre: str = Field(max_length=50)
    apellidos: str = Field(max_length=100)
    tipo_documento: TipoDocumento
    numero_documento: str = Field(max_length=20)
    direccion: str | None = Field(max_length=200, default=None)
    telefono: str | None = Field(max_length=20, default=None)
    email: EmailStr | None = Field(max_length=100, default=None)
    fecha_nacimiento: date | None = None
    nacionalidad: str | None = Field(max_length=50, default=None)
    preferencias: str | None = Field(max_length=500, default=None)
    estado: EstadoCliente = Field(default=EstadoCliente.ACTIVO)


class Cliente(ClienteBase, table=True):
    __tablename__ = "clientes"
    id: int | None = Field(default=None, primary_key=True)
    fecha_registro: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    contactos_emergencia: list["ContactoEmergencia"] = Relationship(
        back_populates="cliente",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
