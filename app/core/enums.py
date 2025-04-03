from enum import Enum


# Enums para el modulo de gestion de clientes
class EstadoCliente(str, Enum):
    ACTIVO = "Activo"
    INACTIVO = "Inactivo"


class TipoDocumento(str, Enum):
    CARNET_IDENTIDAD = "Carnet de Identidad"
    PASAPORTE = "Pasaporte"
    OTRO = "Otro"


# Enums para el módulo de autenticación y seguridad
class UserStatus(str, Enum):
    ACTIVE = "Active"
    INACTIVE = "Inactive"
    LOCKED = "Locked"
    PASSWORD_EXPIRED = "PasswordExpired"
    PENDING_ACTIVATION = "PendingActivation"


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    RESET_PASSWORD = "reset_password"
    VERIFY_EMAIL = "verify_email"
