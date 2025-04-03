from functools import lru_cache
from typing import Optional

from pydantic import EmailStr, Field, ValidationInfo, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Configuración general de la aplicación
    PROJECT_NAME: str = "Sistema de Ventas Ama Wara"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"

    # Configuración de seguridad
    JWT_SECRET_KEY: str = Field(...)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PASSWORD_RESET_TOKEN_EXPIRE_HOURS: int = 24

    # Políticas de seguridad
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_MAX_AGE_DAYS: int = 90
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5

    # Configuración de la base de datos
    DB_HOST: str
    DB_USERNAME: str
    DB_PASSWORD: str
    DB_DATABASE: str
    DB_PORT: str
    DATABASE_URL: Optional[str] = None
    SQL_ECHO: bool = False

    # Configuración de correo electrónico
    MAIL_SERVER: Optional[str] = None
    MAIL_PORT: Optional[int] = None
    MAIL_USERNAME: Optional[str] = None
    MAIL_PASSWORD: Optional[str] = None
    MAIL_FROM: Optional[EmailStr] = None
    MAIL_TLS: bool = True
    MAIL_SSL: bool = False

    # Configuración de CORS
    CORS_ORIGINS: list[str] = ["*"]

    # Entorno
    ENVIRONMENT: str = "development"

    @field_validator("DATABASE_URL", mode="before")
    def validate_database_url(cls, v: str | None, values: ValidationInfo) -> str:
        if v:
            return v

        # Construir URL de conexión si no está definida
        return (
            f"postgresql://{values.data['DB_USERNAME']}:{values.data['DB_PASSWORD']}@"
            f"{values.data['DB_HOST']}:{values.data['DB_PORT']}/{values.data['DB_DATABASE']}"
        )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache
def get_settings() -> Settings:
    """
    Retorna una instancia de la configuración con caché.

    Este enfoque usa @lru_cache para evitar cargar la configuración
    cada vez que se necesita, mejorando el rendimiento.
    """
    return Settings()
