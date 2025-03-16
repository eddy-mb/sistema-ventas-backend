from typing import Generic, List, Optional, TypeVar

from pydantic import BaseModel
from pydantic.generics import GenericModel

T = TypeVar("T")


class StandardResponse(GenericModel, Generic[T]):
    """
    Formato de respuesta estándar para todas las APIs.

    Attributes:
        status: Estado de la respuesta ('success' o 'error')
        message: Mensaje descriptivo
        data: Datos de la respuesta (opcional)
    """

    status: str
    message: str
    data: Optional[T] = None


class ErrorDetail(BaseModel):
    """
    Detalle de error para validaciones fallidas.

    Attributes:
        loc: Ubicación del error (campo)
        msg: Mensaje de error
        type: Tipo de error
    """

    loc: List[str]
    msg: str
    type: str


class ValidationErrorResponse(BaseModel):
    """
    Respuesta para errores de validación.

    Attributes:
        status: Estado de la respuesta (siempre 'error')
        message: Mensaje descriptivo
        errors: Diccionario de errores por campo
    """

    status: str = "error"
    message: str
    errors: dict[str, str]
