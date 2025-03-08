from app.models.clientes.contacto_emergencia_model import (
    ContactoEmergenciaBase,
)


class ContactoEmergenciaCreate(ContactoEmergenciaBase):
    pass


class ContactoEmergenciaRead(ContactoEmergenciaCreate):
    id: int
    cliente_id: int
