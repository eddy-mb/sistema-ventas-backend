from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY


async def custom_exception_validate(
    request: Request, exc: RequestValidationError
):
    errors = {}

    # Mapeo de errores comunes a mensajes personalizados
    error_messages = {
        "max_length": "debe tener máximo {limit} caracteres",
        "min_length": "debe tener mínimo {limit} caracteres",
        "pattern": "formato inválido",
        "required": "es obligatorio",
        "type_error": "tipo de dato inválido",
    }

    for error in exc.errors():
        # Obtener información del error
        field_path = error["loc"]
        field = field_path[-1] if len(field_path) > 1 else field_path[0]
        error_type = error["type"]

        # Crear mensaje personalizado basado en el tipo de error
        if "max_length" in error_type:
            limit = error.get("ctx", {}).get("limit", "")
            message = error_messages["max_length"].format(limit=limit)
        elif "min_length" in error_type:
            limit = error.get("ctx", {}).get("limit", "")
            message = error_messages["min_length"].format(limit=limit)
        elif "pattern" in error_type:
            message = error_messages["pattern"]
        elif error_type == "missing":
            message = error_messages["required"]
        elif "type_error" in error_type:
            message = error_messages["type_error"]
        else:
            # Usar el mensaje original para otros casos
            message = error["msg"]

        # Añadir al diccionario de errores
        errors[field] = message

    # Devolver respuesta con formato uniforme
    return JSONResponse(
        status_code=HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": "error",
            "message": "Datos de entrada inválidos",
            "errors": errors,
        },
    )
