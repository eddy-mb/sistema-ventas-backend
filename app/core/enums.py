from enum import Enum


# Enums para el modulo de gestion de clientes
class EstadoCliente(str, Enum):
    ACTIVO = "activo"
    INACTIVO = "inactivo"


class TipoDocumento(str, Enum):
    CARNET_IDENTIDAD = "carnet de identidad"
    PASAPORTE = "pasaporte"
    OTRO = "otro"


# Enums para el módulo de autenticación y seguridad
class EstadoUsuario(str, Enum):
    ACTIVO = "activo"
    INACTIVO = "inactivo"
    BLOQUEADO = "bloqueado"
    PASSWORD_EXPIRADO = "password_expirado"
    ACTIVACION_PENDIENTE = "activacion_pendiente"


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    RESET_PASSWORD = "reset_password"
    VERIFY_EMAIL = "verify_email"


class Roles(str, Enum):
    GERENTE = "gerente"
    ADMIN = "admin"
    COUNTER = "counter"
    GESTOR_DE_PAQUETES = "gestor de paquetes"
