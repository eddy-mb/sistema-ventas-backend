from enum import Enum


# Enums para el modulo de gestion de clientes
class EstadoCliente(str, Enum):
    ACTIVO = "Activo"
    INACTIVO = "Inactivo"


class TipoDocumento(str, Enum):
    CARNET_IDENTIDAD = "Carnet de Identidad"
    PASAPORTE = "Pasaporte"
    OTRO = "Otro"
