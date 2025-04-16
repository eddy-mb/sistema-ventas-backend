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
class EstadoUsuario(str, Enum):
    ACTIVO = "Activo"
    INACTIVO = "Inactivo"
    BLOQUEADO = "Bloqueado"
    PASSWORD_Expirado = "Password_expirado"
    ACTIVACION_PEDIENTE = "Activación pendiente"


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    RESET_PASSWORD = "reset_password"
    VERIFY_EMAIL = "verify_email"


class Roles(str, Enum):
    ADMINISTRADOR = "Administrador"
    GERENTE = "Gerente"
    COUNTER = "Counter"
    GESTOR_PAQUETES = "Gestor de paquetes"
