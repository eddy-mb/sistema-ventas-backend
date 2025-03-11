from datetime import date, datetime

from pydantic import EmailStr
from sqlmodel import SQLModel

from app.core.enums import EstadoCliente, TipoDocumento
from app.models.clientes.cliente_model import ClienteBase
from app.schemas.clientes.contacto_emergencia_schema import (
    ContactoEmergenciaCreate,
    ContactoEmergenciaRead,
)


class ClienteCreate(ClienteBase):

    contactos_emergencia: list[ContactoEmergenciaCreate] | None = None


class ClienteRead(ClienteBase):
    id: int
    fecha_registro: datetime


class ClienteUpdate(ClienteBase):
    """
    Nose incluyen tipo_documento y numero_documento por que son datos sensibles
    - Funcionan como identificadores naturales del cliente
    - Podrían estar referenciados en documentos de ventas, auditoría o
    registros legales
    - Cambiarlos podría causar problemas de integridad de datos
    """

    nombre: str | None
    apellidos: str | None
    direccion: str | None
    telefono: str | None
    email: EmailStr | None
    fecha_nacimiento: date | None
    nacionalidad: str | None
    preferencias: str | None
    estado: EstadoCliente | None


class ClienteReadWithContacts(ClienteRead):
    contactos_emergencia: list[ContactoEmergenciaRead] = []


class ClienteSearchParams(SQLModel):
    nombre: str | None
    apellidos: str | None
    tipo_documento: TipoDocumento | None
    numero_documento: str | None
    email: str | None
    telefono: str | None
    nacionalidad: str | None
    estado: EstadoCliente | None = EstadoCliente.ACTIVO
