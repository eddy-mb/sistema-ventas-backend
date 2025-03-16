from typing import List, Optional

from fastapi import APIRouter, Depends, Query, status

from app.dependencies.db import SessionDep
from app.schemas.clientes.cliente_schema import (
    ClienteCreate,
    ClienteRead,
    ClienteReadWithContacts,
    ClienteSearchParams,
    ClienteUpdate,
)
from app.schemas.clientes.contacto_emergencia_schema import (
    ContactoEmergenciaCreate,
    ContactoEmergenciaRead,
)
from app.schemas.common_schema import StandardResponse
from app.services.cliente_service import ClienteService
from app.utils.pagination import PagedResponse, PaginationParams, paginate_results

router = APIRouter(prefix="/clientes", tags=["Clientes"])


@router.post("", response_model=StandardResponse[ClienteRead], status_code=status.HTTP_201_CREATED)
def crear_cliente(cliente: ClienteCreate, db: SessionDep):
    """
    Crea un nuevo cliente en el sistema.

    - **nombre**: Nombre del cliente
    - **apellidos**: Apellidos del cliente
    - **tipo_documento**: Tipo de documento de identidad
    - **numero_documento**: Número de documento de identidad
    - **direccion**: Dirección postal (opcional)
    - **telefono**: Teléfono de contacto (opcional, pero obligatorio si no hay email)
    - **email**: Correo electrónico (opcional, pero obligatorio si no hay teléfono)
    - **fecha_nacimiento**: Fecha de nacimiento (opcional)
    - **nacionalidad**: País de nacionalidad (opcional)
    - **preferencias**: Preferencias del cliente (opcional)
    """
    cliente_service = ClienteService(db)
    nuevo_cliente = cliente_service.crear_cliente(cliente)

    return StandardResponse(
        status="success", message="Cliente creado exitosamente", data=nuevo_cliente
    )


@router.post("/{cliente_id}/contactos", response_model=StandardResponse[ContactoEmergenciaRead])
def agregar_contacto_emergencia(
    cliente_id: int, contacto: ContactoEmergenciaCreate, db: SessionDep
):
    """
    Agrega un contacto de emergencia a un cliente existente.

    - **nombre**: Nombre del contacto
    - **relacion**: Relación con el cliente
    - **telefono**: Teléfono del contacto
    """
    cliente_service = ClienteService(db)
    nuevo_contacto = cliente_service.agregar_contacto_emergencia(cliente_id, contacto)

    return StandardResponse(
        status="success",
        message="Contacto de emergencia agregado exitosamente",
        data=nuevo_contacto,
    )


@router.get("", response_model=StandardResponse[PagedResponse[ClienteRead]])
def buscar_clientes(
    db: SessionDep,
    pagination: PaginationParams = Depends(),
    nombre: Optional[str] = None,
    apellidos: Optional[str] = None,
    tipo_documento: Optional[str] = None,
    numero_documento: Optional[str] = None,
    email: Optional[str] = None,
    telefono: Optional[str] = None,
    nacionalidad: Optional[str] = None,
    estado: Optional[str] = Query(None, description="Estado del cliente (Activo/Inactivo)"),
):
    """
    Busca clientes según los criterios especificados.

    - Se pueden combinar múltiples criterios para refinar la búsqueda
    - Los resultados se paginan según los parámetros skip y limit
    - Por defecto, solo se muestran clientes activos
    """
    # Construir objeto de parámetros de búsqueda
    search_params = ClienteSearchParams(
        nombre=nombre,
        apellidos=apellidos,
        tipo_documento=tipo_documento,
        numero_documento=numero_documento,
        email=email,
        telefono=telefono,
        nacionalidad=nacionalidad,
        estado=estado,
    )

    cliente_service = ClienteService(db)
    clientes, total_count = cliente_service.buscar_clientes(
        search_params, pagination.skip, pagination.limit
    )

    # Crear respuesta paginada
    paged_response = paginate_results(clientes, total_count, pagination)

    return StandardResponse(
        status="success", message="Clientes recuperados exitosamente", data=paged_response
    )


@router.get("/{cliente_id}", response_model=StandardResponse[ClienteReadWithContacts])
def obtener_cliente(cliente_id: int, db: SessionDep):
    """
    Obtiene los datos completos de un cliente específico, incluyendo sus contactos de emergencia.
    """
    cliente_service = ClienteService(db)
    cliente = cliente_service.obtener_cliente(cliente_id)
    # Cargar contactos de emergencia
    contactos = cliente_service.obtener_contactos_emergencia(cliente_id)

    # Construir respuesta combinada
    cliente_dict = {**cliente.model_dump(), "contactos_emergencia": contactos}

    return StandardResponse(
        status="success", message="Cliente recuperado exitosamente", data=cliente_dict
    )


@router.put("/{cliente_id}", response_model=StandardResponse[ClienteRead])
def actualizar_cliente(cliente_id: int, cliente: ClienteUpdate, db: SessionDep):
    """
    Actualiza los datos de un cliente existente.

    - No se permite modificar el tipo y número de documento
    - Solo se actualizarán los campos incluidos en la solicitud
    """
    cliente_service = ClienteService(db)
    cliente_actualizado = cliente_service.actualizar_cliente(cliente_id, cliente)

    return StandardResponse(
        status="success", message="Cliente actualizado exitosamente", data=cliente_actualizado
    )


@router.delete("/{cliente_id}", response_model=StandardResponse[None])
def eliminar_cliente(cliente_id: int, db: SessionDep):
    """
    Elimina un cliente del sistema (eliminación lógica).

    - Esta operación no elimina físicamente al cliente de la base de datos
    - Los clientes eliminados no aparecerán en las búsquedas habituales
    """
    cliente_service = ClienteService(db)
    cliente_service.eliminar_cliente(cliente_id)

    return StandardResponse(status="success", message="Cliente eliminado exitosamente", data=None)


@router.get(
    "/{cliente_id}/contactos", response_model=StandardResponse[List[ContactoEmergenciaRead]]
)
def obtener_contactos_cliente(cliente_id: int, db: SessionDep):
    """
    Obtiene todos los contactos de emergencia de un cliente específico.
    """
    cliente_service = ClienteService(db)
    contactos = cliente_service.obtener_contactos_emergencia(cliente_id)

    return StandardResponse(
        status="success", message="Contactos de emergencia recuperados exitosamente", data=contactos
    )


@router.delete("/contactos/{contacto_id}", response_model=StandardResponse[None])
def eliminar_contacto_emergencia(contacto_id: int, db: SessionDep):
    """
    Elimina un contacto de emergencia.
    """
    cliente_service = ClienteService(db)
    cliente_service.eliminar_contacto_emergencia(contacto_id)

    return StandardResponse(
        status="success", message="Contacto de emergencia eliminado exitosamente", data=None
    )
