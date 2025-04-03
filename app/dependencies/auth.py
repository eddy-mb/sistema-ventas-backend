from typing import Annotated, List

import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes

from app.core.config import get_settings
from app.core.enums import UserStatus
from app.dependencies.db import SessionDep
from app.models.auth.user_model import User
from app.repositories.auth.user_repository import UserRepository
from app.utils.security import decode_token

settings = get_settings()

# Configuración de OAuth2
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_PREFIX}/auth/login",
    scopes={},  # Aquí se pueden definir scopes predeterminados
)


def get_current_user(
    session: SessionDep,
    token: Annotated[str, Depends(oauth2_scheme)],
) -> User:
    """
    Obtiene el usuario actual a partir del token JWT.

    Args:
        session: Sesión de base de datos
        token: Token JWT de autenticación

    Returns:
        Usuario autenticado

    Raises:
        HTTPException: Si el token es inválido o el usuario no existe
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decodificar token
        payload = decode_token(token)

        # Verificar que sea un token de acceso
        if payload.get("type") != "access":
            raise credentials_exception

        # Obtener ID de usuario del token
        user_id: str = payload.get("sub")
        if not user_id:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    # Buscar usuario en la base de datos
    user_repository = UserRepository(session)
    user = user_repository.get_by_id(int(user_id))

    if not user:
        raise credentials_exception

    # Verificar que el usuario esté activo
    if not user.is_active or user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario inactivo o bloqueado",
        )

    return user


def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """
    Verifica que el usuario actual esté activo.

    Args:
        current_user: Usuario autenticado

    Returns:
        Usuario autenticado y activo

    Raises:
        HTTPException: Si el usuario no está activo
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario inactivo",
        )
    return current_user


def get_current_superuser(current_user: Annotated[User, Depends(get_current_active_user)]) -> User:
    """
    Verifica que el usuario actual sea superusuario.

    Args:
        current_user: Usuario autenticado y activo

    Returns:
        Usuario autenticado, activo y superusuario

    Raises:
        HTTPException: Si el usuario no es superusuario
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="El usuario no tiene permisos de superusuario",
        )
    return current_user


def check_permissions(required_permissions: List[str]):
    """
    Crea una dependencia que verifica que el usuario tenga los permisos requeridos.

    Args:
        required_permissions: Lista de permisos requeridos

    Returns:
        Dependencia que verifica permisos
    """

    def permission_checker(
        security_scopes: SecurityScopes,
        session: SessionDep,
        token: Annotated[str, Depends(oauth2_scheme)],
    ):
        """
        Verifica que el usuario tenga los permisos necesarios.

        Args:
            security_scopes: Scopes de seguridad de FastAPI
            session: Sesión de base de datos
            token: Token JWT de autenticación

        Raises:
            HTTPException: Si el usuario no tiene los permisos necesarios
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            # Decodificar token
            payload = decode_token(token)

            # Verificar que sea un token de acceso
            if payload.get("type") != "access":
                raise credentials_exception

            # Obtener ID de usuario del token
            user_id: str = payload.get("sub")
            if not user_id:
                raise credentials_exception

            # Obtener permisos del token
            token_scopes = payload.get("scopes", [])

            # Verificar que el usuario tenga todos los permisos requeridos
            for permission in required_permissions:
                if permission not in token_scopes:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"No tienes permiso para realizar esta acción: {permission}",
                    )
        except jwt.PyJWTError:
            raise credentials_exception

    return Security(permission_checker)


def has_permission(permission: str):
    """
    Verifica si el usuario tiene un permiso específico.

    Args:
        permission: Código del permiso requerido

    Returns:
        Función de dependencia
    """

    def permission_checker(
        security_scopes: SecurityScopes,
        session: SessionDep,
        token: Annotated[str, Depends(oauth2_scheme)],
    ):
        """
        Verifica que el usuario tenga el permiso necesario.

        Args:
            security_scopes: Scopes de seguridad de FastAPI
            session: Sesión de base de datos
            token: Token JWT de autenticación

        Raises:
            HTTPException: Si el usuario no tiene el permiso necesario
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            # Decodificar token
            payload = decode_token(token)

            # Verificar que sea un token de acceso
            if payload.get("type") != "access":
                raise credentials_exception

            # Obtener ID de usuario del token
            user_id: str = payload.get("sub")
            if not user_id:
                raise credentials_exception

            # Obtener permisos del token
            token_scopes = payload.get("scopes", [])

            # Verificar que el usuario tenga el permiso requerido
            if permission not in token_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"No tienes permiso para realizar esta acción: {permission}",
                )

        except jwt.PyJWTError:
            raise credentials_exception

    return permission_checker
