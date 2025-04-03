from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from jwt import PyJWTError

from app.database.session import get_session
from app.services.auditoria_service import AuditoriaService, TipoAccion


async def security_middleware(request: Request, call_next):
    """
    Middleware para manejar errores de seguridad y auditoría.

    Este middleware detecta errores de autenticación y autorización,
    registrándolos en el sistema de auditoría para su posterior análisis.

    Args:
        request: Objeto Request de FastAPI
        call_next: Función para procesar el siguiente middleware o endpoint

    Returns:
        Respuesta HTTP
    """
    try:
        # Continuar con la solicitud normal
        response = await call_next(request)

        # Si es un error de autorización (403) o autenticación (401),
        # registrar en auditoría
        if response.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN):
            # Obtener información de la solicitud
            path = request.url.path
            method = request.method
            client_host = request.client.host if request.client else "unknown"

            # Obtener encabezado de autorización si existe
            auth_header = request.headers.get("Authorization", "")
            has_token = auth_header.startswith("Bearer ")

            # Datos para el registro de auditoría
            description = (
                f"{'Acceso no autorizado' if response.status_code == 403 else 'Autenticación'} "
                f"fallida en {method} {path}"
            )

            details = {
                "path": path,
                "method": method,
                "client_ip": client_host,
                "has_token": has_token,
                "status_code": response.status_code,
            }

            # Registrar en auditoría asíncronamente
            try:
                # Esto no es ideal en un entorno asíncrono, pero es una solución temporal
                # En una implementación completa, se utilizaría un sistema de mensajería
                # para desacoplar este registro de la solicitud HTTP
                db = next(get_session())
                auditoria_service = AuditoriaService(db)
                auditoria_service.registrar_accion(
                    usuario_id=None,
                    tipo_accion=TipoAccion.OTRO,
                    modulo="Security",
                    entidad="AccessControl",
                    detalles=details,
                    descripcion=description,
                    ip_origen=client_host,
                    resultado=False,
                )
            except Exception:
                # Si falla el registro de auditoría, continuar de todas formas
                # pero en un sistema de producción, esto debería ser logueado
                pass

        return response

    except PyJWTError:
        # Capturar errores de JWT y transformarlos en respuestas adecuadas
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "status": "error",
                "message": "Token inválido o expirado",
                "data": None,
            },
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception:
        # Capturar excepciones no manejadas
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "Error interno del servidor",
                "data": None,
            },
        )


def add_security_middleware(app: FastAPI):
    """Registra el middleware de seguridad en la aplicación."""
    app.middleware("http")(security_middleware)
