from typing import List, Tuple

from fastapi import HTTPException, status
from sqlmodel import Session

from app.models.clientes.cliente_model import Cliente
from app.models.clientes.contacto_emergencia_model import ContactoEmergencia
from app.repositories.clientes.cliente_repository import ClienteRepository
from app.repositories.clientes.contacto_emergencia_repository import (
    ContactoEmergenciaRepository,
)
from app.schemas.clientes.cliente_schema import (
    ClienteCreate,
    ClienteSearchParams,
    ClienteUpdate,
)
from app.schemas.clientes.contacto_emergencia_schema import ContactoEmergenciaCreate
from app.services.auditoria_service import AuditoriaService, TipoAccion
from app.utils.validators import ClienteValidators


class ClienteService:
    """Servicio para la gestión de clientes."""

    def __init__(self, db: Session):
        self.db = db
        self.cliente_repository = ClienteRepository(db)
        self.contacto_emergencia_repository = ContactoEmergenciaRepository(db)
        self.auditoria_service = AuditoriaService(db)

    def crear_cliente(self, cliente_data: ClienteCreate, usuario: str = "sistema") -> Cliente:
        """
        Crea un nuevo cliente.

        Args:
            cliente_data: Datos del cliente a crear.
            usuario: Usuario que realiza la operación.

        Returns:
            Cliente creado.

        Raises:
            HTTPException: Si ya existe un cliente con el
            mismo tipo y número de documento,
                          o si faltan datos de contacto,
                          o si el formato del documento no es válido.
        """
        # Validar que el formato del documento sea válido
        ClienteValidators.validar_format_documento(
            cliente_data.tipo_documento, cliente_data.numero_documento
        )

        # Verificar si ya existe un cliente con el mismo
        # tipo y número de documento
        if ClienteValidators.validar_documento_existe(
            self.db, cliente_data.tipo_documento, cliente_data.numero_documento
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Ya existe un cliente con el documento "
                    f"{cliente_data.tipo_documento}: "
                    f"{cliente_data.numero_documento}"
                ),
            )

        # Validar que al menos uno de los campos de contacto esté presente
        ClienteValidators.validar_al_menos_un_contacto(cliente_data.telefono, cliente_data.email)

        # Crear el cliente
        cliente_dict = cliente_data.model_dump()
        cliente = self.cliente_repository.create(cliente_dict, usuario)

        # Registrar en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=None,  # Posteriormente se implementará la autenticación
            tipo_accion=TipoAccion.CREAR,
            modulo="Clientes",
            entidad="Cliente",
            entidad_id=cliente.id,
            detalles={"datos": cliente_dict},
            descripcion=("Creación de cliente: {cliente.nombre} {cliente.apellidos}"),
        )

        return cliente

    def agregar_contacto_emergencia(
        self,
        cliente_id: int,
        contacto_data: ContactoEmergenciaCreate,
        usuario: str = "sistema",
    ) -> ContactoEmergencia:
        """
        Agrega un contacto de emergencia a un cliente existente.

        Args:
            cliente_id: ID del cliente.
            contacto_data: Datos del contacto de emergencia.
            usuario: Usuario que realiza la operación.

        Returns:
            Contacto de emergencia creado.

        Raises:
            HTTPException: Si el cliente no existe.
        """
        # Verificar que el cliente existe
        cliente = self.cliente_repository.get_by_id(cliente_id)
        if not cliente:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Cliente con ID {cliente_id} no encontrado",
            )

        # Crear el contacto de emergencia
        contacto_dict = contacto_data.model_dump()
        contacto_dict["cliente_id"] = cliente_id

        contacto = self.contacto_emergencia_repository.create(contacto_dict, usuario)

        # Registrar en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=None,
            tipo_accion=TipoAccion.CREAR,
            modulo="Clientes",
            entidad="ContactoEmergencia",
            entidad_id=contacto.id,
            detalles={"datos": contacto_dict, "cliente_id": cliente_id},
            descripcion=("Creación de contacto de emergencia para cliente ID: " f"{cliente_id}"),
        )

        return contacto

    def obtener_cliente(self, cliente_id: int) -> Cliente:
        """
        Obtiene un cliente por su ID.

        Args:
            cliente_id: ID del cliente.

        Returns:
            Cliente o None si no se encuentra.

        Raises:
            HTTPException: Si el cliente no existe.
        """
        cliente = self.cliente_repository.get_by_id(cliente_id)
        if not cliente:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Cliente con ID {cliente_id} no encontrado",
            )
        return cliente

    def actualizar_cliente(
        self,
        cliente_id: int,
        cliente_data: ClienteUpdate,
        usuario: str = "sistema",
    ) -> Cliente:
        """
        Actualiza los datos de un cliente existente.

        Args:
            cliente_id: ID del cliente a actualizar.
            cliente_data: Datos actualizados del cliente.
            usuario: Usuario que realiza la operación.

        Returns:
            Cliente actualizado.

        Raises:
            HTTPException: Si el cliente no existe.
        """
        # Verificar que el cliente existe
        cliente = self.cliente_repository.get_by_id(cliente_id)
        if not cliente:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Cliente con ID {cliente_id} no encontrado",
            )

        # Actualizar solo los campos presentes en la solicitud
        update_data = cliente_data.model_dump(exclude_unset=True)

        # Si se intenta actualizar a estado inactivo,
        # verificar que no tenga ventas activas
        # Esto se implementaría aquí si tuviéramos el módulo de ventas

        # Actualizar el cliente
        cliente_actualizado = self.cliente_repository.update(cliente_id, update_data, usuario)

        # Registrar en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=None,
            tipo_accion=TipoAccion.ACTUALIZAR,
            modulo="Clientes",
            entidad="Cliente",
            entidad_id=cliente_id,
            detalles={"datos_actualizados": update_data},
            descripcion=f"Actualización de cliente ID: {cliente_id}",
        )

        return cliente_actualizado

    def eliminar_cliente(self, cliente_id: int, usuario: str = "sistema") -> bool:
        """
        Elimina (lógicamente) un cliente.

        Args:
            cliente_id: ID del cliente a eliminar.
            usuario: Usuario que realiza la operación.

        Returns:
            True si se eliminó correctamente, False si no.

        Raises:
            HTTPException: Si el cliente no existe o no se puede eliminar.
        """
        # Verificar que el cliente existe
        cliente = self.cliente_repository.get_by_id(cliente_id)
        if not cliente:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Cliente con ID {cliente_id} no encontrado",
            )

        # Verificar si el cliente tiene ventas asociadas (no implementado aún)
        # Esto se implementaría aquí cuando tengamos el módulo de ventas

        # Eliminar el cliente
        resultado = self.cliente_repository.delete(cliente_id, usuario)
        if not resultado:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="No se pudo eliminar el cliente",
            )

        # Registrar en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=None,
            tipo_accion=TipoAccion.ELIMINAR,
            modulo="Clientes",
            entidad="Cliente",
            entidad_id=cliente_id,
            detalles={"cliente_id": cliente_id},
            descripcion=f"Eliminación lógica de cliente ID: {cliente_id}",
        )

        return True

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
        return self.cliente_repository.buscar_clientes(params, skip, limit)

    def obtener_contactos_emergencia(self, cliente_id: int) -> List[ContactoEmergencia]:
        """
        Obtiene todos los contactos de emergencia de un cliente.

        Args:
            cliente_id: ID del cliente.

        Returns:
            Lista de contactos de emergencia.

        Raises:
            HTTPException: Si el cliente no existe.
        """
        # Verificar que el cliente existe
        cliente = self.cliente_repository.get_by_id(cliente_id)
        if not cliente:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Cliente con ID {cliente_id} no encontrado",
            )

        return self.contacto_emergencia_repository.get_by_cliente_id(cliente_id)

    def eliminar_contacto_emergencia(self, contacto_id: int, usuario: str = "sistema") -> bool:
        """
        Elimina un contacto de emergencia.

        Args:
            contacto_id: ID del contacto a eliminar.
            usuario: Usuario que realiza la operación.

        Returns:
            True si se eliminó correctamente, False si no.

        Raises:
            HTTPException: Si el contacto no existe.
        """
        # Verificar que el contacto existe
        contacto = self.contacto_emergencia_repository.get_by_id(contacto_id)
        if not contacto:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(f"Contacto de emergencia con ID {contacto_id} " "no encontrado"),
            )

        # Obtener el ID del cliente para la auditoría
        cliente_id = contacto.cliente_id

        # Eliminar el contacto
        resultado = self.contacto_emergencia_repository.delete(contacto_id, usuario)
        if not resultado:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="No se pudo eliminar el contacto de emergencia",
            )

        # Registrar en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=None,
            tipo_accion=TipoAccion.ELIMINAR,
            modulo="Clientes",
            entidad="ContactoEmergencia",
            entidad_id=contacto_id,
            detalles={"contacto_id": contacto_id, "cliente_id": cliente_id},
            descripcion=(
                "Eliminación de contacto de emergencia ID: "
                f"{contacto_id} del cliente ID: {cliente_id}"
            ),
        )

        return True
