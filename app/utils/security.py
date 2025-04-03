from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union

import jwt
from passlib.context import CryptContext

from app.core.config import get_settings

# Configuración para manejo de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configuración de JWT
settings = get_settings()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica que la contraseña plana coincida con el hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Genera un hash para la contraseña proporcionada."""
    return pwd_context.hash(password)


def create_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
    token_type: str = "access",
    scopes: Optional[list] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Genera un token JWT.

    Args:
        subject: Identificador del sujeto (normalmente user_id)
        expires_delta: Tiempo de expiración del token
        token_type: Tipo de token (access, refresh, etc.)
        scopes: Lista de alcances/permisos
        extra_claims: Claims adicionales para incluir en el token

    Returns:
        Token JWT como string
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    expire = datetime.now(timezone.utc) + expires_delta

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": token_type,
        "iat": datetime.now(timezone.utc),
    }

    if scopes:
        to_encode["scopes"] = scopes

    if extra_claims:
        to_encode.update(extra_claims)

    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decodifica un token JWT.

    Args:
        token: Token JWT a decodificar

    Returns:
        Payload del token como diccionario

    Raises:
        jwt.PyJWTError: Si el token es inválido o ha expirado
    """
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])


def create_access_token(subject: Union[str, Any], scopes: Optional[list] = None) -> str:
    """Crea un token de acceso (corta duración)."""
    expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return create_token(subject, expires, "access", scopes)


def create_refresh_token(subject: Union[str, Any]) -> str:
    """Crea un token de actualización (larga duración)."""
    expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return create_token(subject, expires, "refresh")


def create_password_reset_token(subject: Union[str, Any]) -> str:
    """Crea un token para restablecer contraseña."""
    expires = timedelta(hours=settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS)
    return create_token(subject, expires, "reset_password")
