from typing import TYPE_CHECKING

from sqlmodel import Field, Relationship, SQLModel

from app.models.auditoria.base_model import BaseModel

if TYPE_CHECKING:
    from .cliente_model import Cliente


class ContactoEmergenciaBase(SQLModel):
    nombre: str = Field(min_length=3, max_length=50)
    relacion: str = Field(min_length=3, max_length=50)
    telefono: str = Field(min_length=3, max_length=20)


class ContactoEmergencia(ContactoEmergenciaBase, BaseModel, table=True):

    __tablename__ = "contactos_emergencia"
    __table_args__ = {"schema": "cliente"}

    cliente_id: int = Field(foreign_key="cliente.clientes.id")

    # Relationships
    cliente: "Cliente" = Relationship(back_populates="contactos_emergencia")
