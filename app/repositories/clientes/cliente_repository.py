from typing import List, Optional, Tuple, Type

from sqlalchemy import func
from sqlmodel import col, select

from app.models.clientes.cliente_model import Cliente
from app.repositories.base_repository import BaseRepository
from app.schemas.clientes.cliente_schema import ClienteSearchParams


class ClienteRepository(BaseRepository[Cliente]):
    """Repositorio para operaciones de acceso a datos de clientes."""

    def _get_model_class(self) -> Type[Cliente]:
        return Cliente

    def buscar_por_tipo_y_numero_documento(
        self, tipo_documento: str, numero_documento: str
    ) -> Optional[Cliente]:
        """
        Busca un cliente por su tipo y número de documento.

        Args:
            tipo_documento: Tipo de documento del cliente.
            numero_documento: Número de documento del cliente.

        Returns:
            Cliente o None si no se encuentra.
        """
        query = select(Cliente).where(
            Cliente.tipo_documento == tipo_documento,
            Cliente.numero_documento == numero_documento,
            col(Cliente.estado_audit).is_(True),
        )
        return self.db.exec(query).first()

    def _construir_query_base(self, params: ClienteSearchParams):
        """
        Construye la consulta base con filtros según los parámetros.

        Args:
            params: Parámetros de búsqueda.

        Returns:
            Consulta SQLModel con filtros aplicados.
        """
        query = select(Cliente).where(col(Cliente.estado_audit).is_(True))

        # Aplicar filtros si están presentes en los parámetros
        if params.nombre:
            query = query.where(col(Cliente.nombre).ilike(f"%{params.nombre}%"))

        if params.apellidos:
            query = query.where(col(Cliente.apellidos).ilike(f"%{params.apellidos}%"))

        if params.tipo_documento:
            query = query.where(Cliente.tipo_documento == params.tipo_documento)

        if params.numero_documento:
            query = query.where(Cliente.numero_documento == params.numero_documento)

        if params.email:
            query = query.where(Cliente.email == params.email)

        if params.telefono:
            query = query.where(Cliente.telefono == params.telefono)

        if params.nacionalidad:
            query = query.where(col(Cliente.nacionalidad).ilike(f"%{params.nacionalidad}%"))

        if params.estado:
            query = query.where(Cliente.estado == params.estado)

        return query

    def buscar_clientes(
        self, params: ClienteSearchParams, skip: int = 0, limit: int = 100
    ) -> Tuple[List[Cliente], int]:
        """
        Busca clientes según los parámetros proporcionados con paginación.

        Args:
            params: Parámetros de búsqueda.
            skip: Número de registros a omitir.
            limit: Número máximo de registros a devolver.

        Returns:
            Tupla con lista de clientes que coinciden con
            los criterios y el total de registros.
        """
        # Construir la consulta base con filtros
        query = self._construir_query_base(params)

        # Consulta para contar el total de registros
        count_query = select(func.count()).select_from(query.alias("count_query"))
        total_count = self.db.exec(count_query).one()

        # Aplicar ordenamiento y paginación
        query = query.order_by(Cliente.apellidos, Cliente.nombre)
        query = query.offset(skip).limit(limit)

        # Ejecutar la consulta
        clientes = list(self.db.exec(query).all())

        return clientes, total_count
