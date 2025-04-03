"""
Script para crear los esquemas de base de datos para el sistema de ventas.

Este script debe ejecutarse antes de realizar cualquier migración o creación de tablas.
Ejecutar con: python -m scripts.create_schemas
"""

import os
import sys

from sqlalchemy import text
from sqlmodel import Session

# Agregar el directorio raíz al path para poder importar los módulos de la aplicación
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database.session import engine  # noqa

# Definición de esquemas a crear
SCHEMAS = [
    "auth",  # Autenticación, usuarios, roles, permisos
    "cliente",  # Clientes y contactos de emergencia
    "producto",  # Productos, categorías, proveedores
    "venta",  # Ventas, cotizaciones, reservas
    "auditoria",  # Logs de auditoría y trazabilidad
]


def create_schemas():
    """Crea los esquemas de base de datos si no existen."""
    print("Creando esquemas en la base de datos...")

    with Session(engine) as session:
        for schema in SCHEMAS:
            # Verificar si el esquema ya existe
            q = f"SELECT schema_name FROM information_schema.schemata WHERE schema_name='{schema}'"
            result = session.exec(text(q)).fetchone()

            if result:
                print(f"El esquema '{schema}' ya existe.")
                continue

            # Crear el esquema
            session.exec(text(f"CREATE SCHEMA IF NOT EXISTS {schema}"))
            print(f"Esquema '{schema}' creado exitosamente.")

        # Confirmar los cambios
        session.commit()

    print("Creación de esquemas completada.")


if __name__ == "__main__":
    create_schemas()
