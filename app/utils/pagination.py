from typing import Generic, List, TypeVar

from fastapi import Query
from pydantic import BaseModel
from pydantic.generics import GenericModel

T = TypeVar("T")


class PaginationParams:
    """Clase de utilidad para parámetros de paginación en endpoints."""

    def __init__(
        self,
        skip: int = Query(
            0,
            ge=0,
            description="Número de registros a omitir (para paginación)",
        ),
        limit: int = Query(
            20,
            ge=1,
            le=100,
            description="Número máximo de registros a devolver",
        ),
    ):
        self.skip = skip
        self.limit = limit


class PageInfo(BaseModel):
    """Información de paginación."""

    total: int
    page: int
    pages: int
    has_next: bool
    has_prev: bool
    items_per_page: int


class PagedResponse(GenericModel, Generic[T]):
    """Respuesta paginada genérica."""

    items: List[T]
    page_info: PageInfo


def paginate_results(
    items: List[T], total_count: int, params: PaginationParams
) -> PagedResponse[T]:
    """
    Pagina una lista de resultados.

    Args:
        items: Lista de elementos ya paginados.
        total_count: Número total de elementos (sin paginación).
        params: Parámetros de paginación.

    Returns:
        Respuesta paginada con metadatos.
    """
    # Calcular página actual (basada en 1)
    page = (params.skip // params.limit) + 1 if params.limit > 0 else 1

    # Calcular número total de páginas
    pages = (total_count + params.limit - 1) // params.limit if params.limit > 0 else 1

    # Determinar si hay páginas previas o siguientes
    has_prev = page > 1
    has_next = page < pages

    # Crear objeto de información de paginación
    page_info = PageInfo(
        total=total_count,
        page=page,
        pages=pages,
        has_next=has_next,
        has_prev=has_prev,
        items_per_page=params.limit,
    )

    # Crear respuesta paginada
    return PagedResponse(items=items, page_info=page_info)
