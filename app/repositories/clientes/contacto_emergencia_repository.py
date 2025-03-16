from typing import List, Type

from sqlmodel import col, select

from app.models.clientes.contacto_emergencia_model import ContactoEmergencia
from app.repositories.base_repository import BaseRepository


class ContactoEmergenciaRepository(BaseRepository[ContactoEmergencia]):
    """Repositorio para operaciones de acceso a datos
    de contactos de emergencia.
    """

    def _get_model_class(self) -> Type[ContactoEmergencia]:
        return ContactoEmergencia

    def get_by_cliente_id(self, cliente_id: int) -> List[ContactoEmergencia]:
        """
        Recupera todos los contactos de emergencia para un cliente específico.

        Args:
            cliente_id: ID del cliente.

        Returns:
            Lista de contactos de emergencia.
        """
        query = select(ContactoEmergencia).where(
            ContactoEmergencia.cliente_id == cliente_id,
            col(ContactoEmergencia._estado).is_(True),
        )
        return list(self.db.exec(query).all())
