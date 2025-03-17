import re

from fastapi import HTTPException, status
from sqlmodel import Session, col, select

from app.models.clientes.cliente_model import Cliente


class ClienteValidators:
    """Clase con validadores para el modelo Cliente."""

    @staticmethod
    def validar_documento_existe(
        db: Session,
        tipo_documento: str,
        numero_documento: str,
        cliente_id: int | None = None,
    ) -> bool:
        """
        Valida si ya existe un cliente con el mismo tipo y número de documento.

        Args:
            db: Sesión de base de datos.
            tipo_documento: Tipo de documento.
            numero_documento: Número de documento.
            cliente_id: ID del cliente actual (para excluirlo de
            la validación en actualizaciones).

        Returns:
            True si ya existe un cliente con ese documento, False si no.
        """
        query = select(Cliente).where(
            Cliente.tipo_documento == tipo_documento,
            Cliente.numero_documento == numero_documento,
            col(Cliente.estado_audit).is_(True),
        )

        # Si es una actualización, excluir el cliente actual
        if cliente_id:
            query = query.where(Cliente.id != cliente_id)

        result = db.exec(query).first()
        return result is not None

    @staticmethod
    def validar_format_documento(tipo_documento: str, numero_documento: str) -> bool:
        """
        Valida el formato del número de documento según su tipo.

        Args:
            tipo_documento: Tipo de documento.
            numero_documento: Número de documento.

        Returns:
            True si el formato es válido, False si no.

        Raises:
            HTTPException: Si el formato del documento no es válido.
        """
        if tipo_documento == "Carnet de Identidad":
            # Formato típico: 1234567-1A
            if not re.match(r"^\d{7}-\d[A-Z]$", numero_documento):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=(
                        "Formato de Carnet de Identidad inválido. Debe tener formato: 1234567-1A"  # noqa
                    ),
                )
        elif tipo_documento == "Pasaporte":
            # Formato típico: AA000000 (2 letras seguidas de 6 dígitos)
            if not re.match(r"^[A-Z]{2}\d{6}$", numero_documento):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=("Formato de Pasaporte inválido. Debe tener formato: AA000000",),  # noqa
                )

        return True

    @staticmethod
    def validar_al_menos_un_contacto(telefono: str | None = None, email: str | None = None) -> bool:
        """
        Valida que haya al menos un medio de contacto (teléfono o email).

        Args:
            telefono: Número de teléfono.
            email: Dirección de correo electrónico.

        Returns:
            True si hay al menos un medio de contacto, False si no.

        Raises:
            HTTPException: Si no hay ningún medio de contacto.
        """
        if not telefono and not email:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=("Debe proporcionar al menos un medio " "de contacto (teléfono o email)"),
            )

        return True
