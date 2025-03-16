import json
from enum import Enum
from typing import Any, Dict, Optional

from sqlmodel import Session

from app.models.auditoria.log_model import LogAuditoria
from app.utils.helpers import get_current_timestamp


class TipoAccion(str, Enum):
    """Tipo de acción para el registro de auditoría."""

    CREAR = "CREAR"
    ACTUALIZAR = "ACTUALIZAR"
    ELIMINAR = "ELIMINAR"
    CONSULTAR = "CONSULTAR"
    INICIAR_SESION = "INICIAR_SESION"
    CERRAR_SESION = "CERRAR_SESION"
    EXPORTAR = "EXPORTAR"
    OTRO = "OTRO"


class AuditoriaService:
    """Servicio para registrar acciones de auditoría en el sistema."""

    def __init__(self, db: Session):
        self.db = db

    def registrar_accion(
        self,
        usuario_id: Optional[int],
        tipo_accion: TipoAccion,
        modulo: str,
        entidad: str,
        entidad_id: Optional[int] = None,
        detalles: Optional[Dict[str, Any]] = None,
        ip_origen: str = "127.0.0.1",
        resultado: bool = True,
        descripcion: Optional[str] = None,
    ) -> LogAuditoria:
        """
        Registra una acción en el log de auditoría.

        Args:
            usuario_id: ID del usuario que realiza la acción
            (None si es sistema).
            tipo_accion: Tipo de acción realizada.
            modulo: Módulo del sistema donde se realiza la acción.
            entidad: Entidad afectada por la acción.
            entidad_id: ID de la entidad afectada (opcional).
            detalles: Datos adicionales sobre la acción.
            ip_origen: IP desde donde se realiza la acción.
            resultado: True si la acción fue exitosa, False si falló.
            descripcion: Descripción adicional de la acción.

        Returns:
            Registro de auditoría creado.
        """
        # Convertir detalles a JSON si están presentes
        detalles_json = json.dumps(detalles) if detalles else None

        # Crear registro de auditoría
        log = LogAuditoria(
            fecha_hora=get_current_timestamp(),
            usuario_id=usuario_id,
            tipo_accion=tipo_accion,
            modulo=modulo,
            entidad=entidad,
            entidad_id=entidad_id,
            detalles=detalles_json,
            ip_origen=ip_origen,
            resultado=resultado,
            descripcion=descripcion,
        )

        # Guardar en la base de datos
        self.db.add(log)
        self.db.commit()
        self.db.refresh(log)

        return log
