"""
Script para inicializar la base de datos con datos básicos de configuración.

Este script crea:
1. Permisos del sistema
2. Roles predeterminados
3. Usuario administrador inicial

Ejecución:
$ python -m scripts.init_db
"""

import os
import sys
from datetime import datetime, timezone

# Agregar el directorio raíz al path para poder importar los módulos de la aplicación
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from typing import TypedDict  # noqa

from sqlmodel import Session, select  # noqa

from app.core.config import get_settings  # noqa
from app.core.enums import UserStatus  # noqa
from app.database.session import engine  # noqa
from app.models.auth.role_model import (  # noqa
    Permission,
    Role,
    RolePermission,
    UserRole,
)
from app.models.auth.user_model import User  # noqa
from app.utils.security import get_password_hash  # noqa

settings = get_settings()


# Definición de permisos por módulo
PERMISSIONS = {
    "Auth": [
        {
            "code": "user:create",
            "name": "Crear usuarios",
            "description": "Permite crear nuevos usuarios en el sistema",
        },
        {
            "code": "user:read",
            "name": "Ver usuarios",
            "description": "Permite ver información de usuarios",
        },
        {
            "code": "user:update",
            "name": "Actualizar usuarios",
            "description": "Permite modificar información de usuarios",
        },
        {
            "code": "user:delete",
            "name": "Eliminar usuarios",
            "description": "Permite eliminar usuarios del sistema",
        },
        {
            "code": "user:manage_roles",
            "name": "Gestionar roles de usuarios",
            "description": "Permite asignar y quitar roles a usuarios",
        },
        {
            "code": "role:create",
            "name": "Crear roles",
            "description": "Permite crear nuevos roles en el sistema",
        },
        {
            "code": "role:read",
            "name": "Ver roles",
            "description": "Permite ver información de roles",
        },
        {
            "code": "role:update",
            "name": "Actualizar roles",
            "description": "Permite modificar información de roles",
        },
        {
            "code": "role:delete",
            "name": "Eliminar roles",
            "description": "Permite eliminar roles del sistema",
        },
        {
            "code": "role:manage_permissions",
            "name": "Gestionar permisos de roles",
            "description": "Permite asignar y quitar permisos a roles",
        },
        {
            "code": "permission:read",
            "name": "Ver permisos",
            "description": "Permite ver información de permisos",
        },
    ],
    "Clientes": [
        {
            "code": "cliente:create",
            "name": "Crear clientes",
            "description": "Permite crear nuevos clientes",
        },
        {
            "code": "cliente:read",
            "name": "Ver clientes",
            "description": "Permite ver información de clientes",
        },
        {
            "code": "cliente:update",
            "name": "Actualizar clientes",
            "description": "Permite modificar información de clientes",
        },
        {
            "code": "cliente:delete",
            "name": "Eliminar clientes",
            "description": "Permite eliminar clientes",
        },
    ],
    "Productos": [
        {
            "code": "producto:create",
            "name": "Crear productos",
            "description": "Permite crear nuevos productos",
        },
        {
            "code": "producto:read",
            "name": "Ver productos",
            "description": "Permite ver información de productos",
        },
        {
            "code": "producto:update",
            "name": "Actualizar productos",
            "description": "Permite modificar información de productos",
        },
        {
            "code": "producto:delete",
            "name": "Eliminar productos",
            "description": "Permite eliminar productos",
        },
        {
            "code": "categoria:manage",
            "name": "Gestionar categorías",
            "description": "Permite gestionar categorías de productos",
        },
        {
            "code": "proveedor:manage",
            "name": "Gestionar proveedores",
            "description": "Permite gestionar proveedores",
        },
        {
            "code": "precio:manage",
            "name": "Gestionar precios",
            "description": "Permite gestionar precios y promociones",
        },
    ],
    "Ventas": [
        {
            "code": "venta:create",
            "name": "Crear ventas",
            "description": "Permite crear nuevas ventas",
        },
        {
            "code": "venta:read",
            "name": "Ver ventas",
            "description": "Permite ver información de ventas",
        },
        {
            "code": "venta:update",
            "name": "Actualizar ventas",
            "description": "Permite modificar información de ventas",
        },
        {
            "code": "venta:cancel",
            "name": "Cancelar ventas",
            "description": "Permite cancelar ventas",
        },
        {
            "code": "cotizacion:manage",
            "name": "Gestionar cotizaciones",
            "description": "Permite gestionar cotizaciones",
        },
        {
            "code": "reserva:manage",
            "name": "Gestionar reservas",
            "description": "Permite gestionar reservas",
        },
    ],
    "Reportes": [
        {
            "code": "reporte:ventas",
            "name": "Ver reportes de ventas",
            "description": "Permite ver reportes de ventas",
        },
        {
            "code": "reporte:clientes",
            "name": "Ver reportes de clientes",
            "description": "Permite ver reportes de clientes",
        },
        {
            "code": "reporte:productos",
            "name": "Ver reportes de productos",
            "description": "Permite ver reportes de productos",
        },
        {
            "code": "reporte:custom",
            "name": "Reportes personalizados",
            "description": "Permite crear y gestionar reportes personalizados",
        },
    ],
    "System": [
        {
            "code": "system:config",
            "name": "Configurar sistema",
            "description": "Permite configurar parámetros del sistema",
        },
        {
            "code": "system:audit",
            "name": "Ver auditoría",
            "description": "Permite ver registros de auditoría",
        },
    ],
}

# Definición manual de permisos por rol
ROLE_PERMISSIONS = {
    "Administrador": None,  # None significa "todos los permisos"
    "Vendedor": [
        "cliente:create",
        "cliente:read",
        "cliente:update",
        "producto:read",
        "venta:create",
        "venta:read",
        "venta:update",
        "cotizacion:manage",
        "reserva:manage",
        "reporte:ventas",
    ],
    "Gerente": [
        "cliente:read",
        "cliente:update",
        "producto:read",
        "venta:read",
        "venta:update",
        "venta:cancel",
        "cotizacion:manage",
        "reserva:manage",
        "reporte:ventas",
        "reporte:clientes",
        "reporte:productos",
        "reporte:custom",
        "system:audit",
    ],
    "Inventario": [
        "producto:create",
        "producto:read",
        "producto:update",
        "producto:delete",
        "categoria:manage",
        "proveedor:manage",
        "precio:manage",
        "reporte:productos",
    ],
}


class AdminUserDict(TypedDict):
    username: str
    email: str
    full_name: str
    password: str
    is_active: bool
    is_superuser: bool
    status: UserStatus


# Usuario administrador inicial
ADMIN_USER: AdminUserDict = {
    "username": "admin",
    "email": "admin@empresa.com",
    "full_name": "Administrador Sistema",
    "password": "Admin123!",  # Esto debe cambiarse después de la primera ejecución
    "is_active": True,
    "is_superuser": True,
    "status": UserStatus.ACTIVE,
}


def create_permissions(session: Session):
    """Crea los permisos predefinidos en la base de datos."""
    existing_perms = session.exec(select(Permission)).all()
    existing_permissions = {perm.code: perm for perm in existing_perms}

    for module, permissions in PERMISSIONS.items():
        for perm_data in permissions:
            # Verificar si el permiso ya existe
            if perm_data["code"] in existing_permissions:
                print(f"Permiso {perm_data['code']} ya existe, omitiendo...")
                continue

            # Crear nuevo permiso
            permission = Permission(
                code=perm_data["code"],
                name=perm_data["name"],
                description=perm_data["description"],
                module=module,
                usuario_creacion="system",
                fecha_creacion=datetime.now(timezone.utc),
            )

            session.add(permission)
            print(f"Creado permiso: {perm_data['code']}")

    session.commit()


def create_roles(session: Session):
    """Crea los roles predefinidos y asigna permisos."""
    # Obtener todos los permisos existentes
    perm_list = session.exec(select(Permission)).all()
    permissions_dict = {perm.code: perm for perm in perm_list}
    all_permissions = list(permissions_dict.values())

    # Crear cada rol definido
    for role_name, permission_codes in ROLE_PERMISSIONS.items():
        # Buscar si el rol ya existe
        role = session.exec(select(Role).where(Role.name == role_name)).first()

        if role:
            print(f"Rol {role_name} ya existe, verificando permisos...")
        else:
            # Crear nuevo rol
            role = Role(
                name=role_name,
                description=f"Rol de {role_name}",
                is_system_role=True,
                usuario_creacion="system",
                fecha_creacion=datetime.now(timezone.utc),
            )
            session.add(role)
            session.flush()  # Para obtener el ID generado
            print(f"Creado rol: {role_name}")

        # Obtener permisos actuales del rol
        current_rp_list = session.exec(
            select(RolePermission).where(RolePermission.role_id == role.id)
        ).all()
        current_permission_ids = {rp.permission_id for rp in current_rp_list}

        # Determinar qué permisos asignar
        if permission_codes is None:
            # Para rol Administrador: todos los permisos
            perms_to_assign = all_permissions
            print(f"Asignando TODOS los permisos al rol {role_name}")
        else:
            # Para otros roles: sólo los permisos especificados
            perms_to_assign = [
                permissions_dict[code] for code in permission_codes if code in permissions_dict
            ]
            print(f"Asignando {len(perms_to_assign)} permisos al rol {role_name}")

        # Asignar permisos que no estén ya asignados
        for permission in perms_to_assign:
            if permission.id in current_permission_ids:
                print(f"Permiso {permission.code} ya asignado a {role_name}, omitiendo...")
                continue

            # Asignar permiso al rol
            role_permission = RolePermission(
                role_id=role.id,
                permission_id=permission.id,
                usuario_creacion="system",
                fecha_creacion=datetime.now(timezone.utc),
            )
            session.add(role_permission)
            print(f"Asignado permiso {permission.code} a rol {role_name}")

    session.commit()


def create_admin_user(session: Session):
    """Crea el usuario administrador inicial si no existe."""
    # Verificar si ya existe
    admin = session.exec(select(User).where(User.username == ADMIN_USER["username"])).first()

    if admin:
        print(f"Usuario administrador {ADMIN_USER['username']} ya existe, omitiendo...")
        return

    # Crear usuario administrador
    admin = User(
        username=ADMIN_USER["username"],
        email=ADMIN_USER["email"],
        full_name=ADMIN_USER["full_name"],
        hashed_password=get_password_hash(ADMIN_USER["password"]),
        is_active=ADMIN_USER["is_active"],
        is_superuser=ADMIN_USER["is_superuser"],
        status=ADMIN_USER["status"],
        failed_login_attempts=0,
        usuario_creacion="system",
        fecha_creacion=datetime.now(timezone.utc),
    )

    session.add(admin)
    session.flush()  # Para obtener el ID generado
    print(f"Creado usuario administrador: {ADMIN_USER['username']}")

    # Asignar rol de administrador
    admin_role = session.exec(select(Role).where(Role.name == "Administrador")).first()
    if admin_role:
        user_role = UserRole(
            user_id=admin.id,
            role_id=admin_role.id,
            usuario_creacion="system",
            fecha_creacion=datetime.now(timezone.utc),
        )
        session.add(user_role)
        print(f"Asignado rol Administrador a usuario {ADMIN_USER['username']}")

    session.commit()


def init_db():
    """Inicializa la base de datos con datos básicos."""
    print("Inicializando base de datos...")

    with Session(engine) as session:
        create_permissions(session)
        create_roles(session)
        create_admin_user(session)

    print("Base de datos inicializada correctamente.")


if __name__ == "__main__":
    init_db()
