from datetime import datetime, timezone
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlmodel import col, select

from app.dependencies.auth import get_current_active_user, has_permission
from app.dependencies.db import SessionDep
from app.models.auth.role_model import Permission, Role, RolePermission, UserRole
from app.models.auth.user_model import User
from app.schemas.auth.auth_schema import (
    PermissionRead,
    RoleCreate,
    RoleRead,
    RoleUpdate,
)
from app.schemas.common_schema import StandardResponse
from app.services.auditoria_service import AuditoriaService, TipoAccion

router = APIRouter(prefix="/roles", tags=["Roles"])


@router.get(
    "",
    response_model=StandardResponse[List[RoleRead]],
    dependencies=[Depends(has_permission("role:read"))],
)
async def get_roles(
    db: SessionDep,
):
    """
    Obtiene todos los roles disponibles en el sistema.

    Requiere permiso: **role:read**
    """
    query = db.query(Role).filter(col(Role.estado_audit).is_(True)).all()

    return StandardResponse(
        status="success",
        message="Roles recuperados exitosamente",
        data=[
            RoleRead(
                id=role.id,
                name=role.name,
                description=role.description,
            )
            for role in query
        ],
    )


@router.post(
    "",
    response_model=StandardResponse[RoleRead],
    dependencies=[Depends(has_permission("role:create"))],
    status_code=status.HTTP_201_CREATED,
)
async def create_role(
    role_data: RoleCreate,
    db: SessionDep,
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    """
    Crea un nuevo rol en el sistema.

    Requiere permiso: **role:create**
    """
    # Verificar si ya existe un rol con el mismo nombre
    query = select(Role).filter(col(Role.name) == role_data.name)
    existing_role = db.exec(query).first()
    if existing_role:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ya existe un rol con ese nombre",
        )

    # Crear el rol
    new_role = Role(
        name=role_data.name,
        description=role_data.description,
        is_system_role=False,
        usuario_creacion=str(current_user.id),
    )

    db.add(new_role)
    db.commit()
    db.refresh(new_role)

    # Registrar en auditoría
    auditoria_service = AuditoriaService(db)
    auditoria_service.registrar_accion(
        usuario_id=current_user.id,
        tipo_accion=TipoAccion.CREAR,
        modulo="Auth",
        entidad="Role",
        entidad_id=new_role.id,
        detalles={"role_name": new_role.name},
        descripcion=f"Creación de rol: {new_role.name}",
        resultado=True,
    )

    return StandardResponse(
        status="success",
        message="Rol creado exitosamente",
        data=RoleRead(
            id=new_role.id,
            name=new_role.name,
            description=new_role.description,
        ),
    )


@router.get(
    "/{role_id}",
    response_model=StandardResponse[RoleRead],
    dependencies=[Depends(has_permission("role:read"))],
)
async def get_role(
    db: SessionDep,
    role_id: int = Path(..., gt=0),
):
    """
    Obtiene información de un rol específico.

    Requiere permiso: **role:read**
    """
    query = select(Role).filter(col(Role.id) == role_id, col(Role.estado_audit).is_(True))
    role = db.exec(query).first()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rol no encontrado",
        )

    return StandardResponse(
        status="success",
        message="Rol recuperado exitosamente",
        data=RoleRead(
            id=role.id,
            name=role.name,
            description=role.description,
        ),
    )


@router.put(
    "/{role_id}",
    response_model=StandardResponse[RoleRead],
    dependencies=[Depends(has_permission("role:update"))],
)
async def update_role(
    db: SessionDep,
    role_data: RoleUpdate,
    role_id: int = Path(..., gt=0),
    current_user: Annotated[User | None, Depends(get_current_active_user)] = None,
):
    """
    Actualiza información de un rol.

    Requiere permiso: **role:update**
    """
    # Obtener el rol a actualizar
    if current_user is None:
        raise HTTPException(status_code=401, detail="Usuario no autenticado")

    query = select(Role).filter(col(Role.id) == role_id, col(Role.estado_audit).is_(True))
    role = db.exec(query).first()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rol no encontrado",
        )

    # No permitir modificar roles del sistema
    if role.is_system_role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No se pueden modificar roles del sistema",
        )

    # Verificar si hay cambio de nombre y si ya existe otro rol con ese nombre
    if role_data.name and role_data.name != role.name:
        query = select(Role).filter(
            col(Role.name) == role_data.name,
            col(Role.id) != role_id,
            col(Role.estado_audit).is_(True),
        )
        existing_role = db.exec(query).first()

        if existing_role:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Ya existe otro rol con ese nombre",
            )

    # Actualizar campos
    update_data = role_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(role, key, value)

    # Actualizar datos de auditoría
    role.usuario_modificacion = str(current_user.id)
    role.fecha_modificacion = datetime.now(timezone.utc)

    db.add(role)
    db.commit()
    db.refresh(role)

    # Registrar en auditoría
    auditoria_service = AuditoriaService(db)
    auditoria_service.registrar_accion(
        usuario_id=current_user.id,
        tipo_accion=TipoAccion.ACTUALIZAR,
        modulo="Auth",
        entidad="Role",
        entidad_id=role.id,
        detalles={"updated_fields": update_data},
        descripcion=f"Actualización de rol ID: {role.id}",
        resultado=True,
    )

    return StandardResponse(
        status="success",
        message="Rol actualizado exitosamente",
        data=RoleRead(
            id=role.id,
            name=role.name,
            description=role.description,
        ),
    )


@router.delete(
    "/{role_id}",
    response_model=StandardResponse[None],
    dependencies=[Depends(has_permission("role:delete"))],
)
async def delete_role(
    db: SessionDep,
    role_id: int = Path(..., gt=0),
    current_user: Annotated[User | None, Depends(get_current_active_user)] = None,
):
    """
    Elimina un rol (desactivación lógica).

    Requiere permiso: **role:delete**
    """
    # Obtener el rol a eliminar
    if current_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no Encontrado")

    query = select(Role).filter(col(Role.id) == role_id, col(Role.estado_audit).is_(True))
    role = db.exec(query).first()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rol no encontrado",
        )

    # No permitir eliminar roles del sistema
    if role.is_system_role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No se pueden eliminar roles del sistema",
        )

    # Verificar si el rol tiene usuarios asignados
    query_user_role = select(UserRole).filter(col(UserRole.role_id) == role_id)
    results = db.exec(query_user_role).all()
    user_count = len(results)

    if user_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No se puede eliminar el rol porque está asignado a {user_count} usuarios",
        )

    # Realizar eliminación lógica
    role.estado_audit = False
    role.usuario_modificacion = str(current_user.id)
    role.fecha_modificacion = datetime.now(timezone.utc)

    db.add(role)
    db.commit()

    # Registrar en auditoría
    auditoria_service = AuditoriaService(db)
    auditoria_service.registrar_accion(
        usuario_id=current_user.id,
        tipo_accion=TipoAccion.ELIMINAR,
        modulo="Auth",
        entidad="Role",
        entidad_id=role_id,
        detalles={"role_name": role.name},
        descripcion=f"Eliminación de rol: {role.name}",
        resultado=True,
    )

    return StandardResponse(
        status="success",
        message="Rol eliminado exitosamente",
        data=None,
    )


@router.get(
    "/{role_id}/permissions",
    response_model=StandardResponse[List[PermissionRead]],
    dependencies=[Depends(has_permission("role:read"))],
)
async def get_role_permissions(
    db: SessionDep,
    role_id: int = Path(..., gt=0),
):
    """
    Obtiene los permisos asignados a un rol.

    Requiere permiso: **role:read**
    """
    # Verificar que el rol existe
    query = select(Role).filter(col(Role.id) == role_id, col(Role.estado_audit).is_(True))
    role = db.exec(query).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rol no encontrado",
        )

    # Obtener permisos del rol
    query_role = (
        select(Permission)
        .join(RolePermission, col(RolePermission.permission_id) == Permission.id)
        .filter(col(RolePermission.role_id) == role_id)
    )
    permissions = db.exec(query_role).all()

    return StandardResponse(
        status="success",
        message="Permisos recuperados exitosamente",
        data=[
            PermissionRead(
                id=permission.id,
                code=permission.code,
                name=permission.name,
                description=permission.description,
                module=permission.module,
            )
            for permission in permissions
        ],
    )


@router.post(
    "/{role_id}/permissions/{permission_id}",
    response_model=StandardResponse[None],
    dependencies=[Depends(has_permission("role:manage_permissions"))],
)
async def assign_permission_to_role(
    db: SessionDep,
    role_id: int = Path(..., gt=0),
    permission_id: int = Path(..., gt=0),
    current_user: Annotated[User | None, Depends(get_current_active_user)] = None,
):
    """
    Asigna un permiso a un rol.

    Requiere permiso: **role:manage_permissions**
    """
    # Verificar que el rol existe
    query = select(Role).filter(col(Role.id) == role_id, col(Role.estado_audit).is_(True))
    role = db.exec(query).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rol no encontrado",
        )

    # Verificar que el permiso existe
    query_permiso = select(Permission).filter(col(Permission.id) == permission_id)
    permission = db.exec(query_permiso).first()
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permiso no encontrado",
        )

    # Verificar que el permiso no esté ya asignado al rol
    permiso_asignado = select(RolePermission).filter(
        col(RolePermission.role_id) == role_id,
        col(RolePermission.permission_id) == permission_id,
    )
    existing = db.exec(permiso_asignado).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El permiso ya está asignado al rol",
        )

    # Crear la asignación
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado.",
        )
    role_permission = RolePermission(
        role_id=role_id,
        permission_id=permission_id,
        usuario_creacion=str(current_user.id),
    )

    db.add(role_permission)
    db.commit()

    # Registrar en auditoría
    auditoria_service = AuditoriaService(db)
    auditoria_service.registrar_accion(
        usuario_id=current_user.id,
        tipo_accion=TipoAccion.CREAR,
        modulo="Auth",
        entidad="RolePermission",
        detalles={
            "role_id": role_id,
            "role_name": role.name,
            "permission_id": permission_id,
            "permission_code": permission.code,
        },
        descripcion=f"Asignación de permiso {permission.code} a rol {role.name}",
        resultado=True,
    )

    return StandardResponse(
        status="success",
        message="Permiso asignado exitosamente",
        data=None,
    )


@router.delete(
    "/{role_id}/permissions/{permission_id}",
    response_model=StandardResponse[None],
    dependencies=[Depends(has_permission("role:manage_permissions"))],
)
async def remove_permission_from_role(
    db: SessionDep,
    role_id: int = Path(..., gt=0),
    permission_id: int = Path(..., gt=0),
    current_user: Annotated[User | None, Depends(get_current_active_user)] = None,
):
    """
    Elimina un permiso de un rol.

    Requiere permiso: **role:manage_permissions**
    """
    # Verificar que el rol existe
    query_rol = select(Role).filter(col(Role.id) == role_id, col(Role.estado_audit).is_(True))
    role = db.exec(query_rol).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rol no encontrado",
        )

    # Verificar que el permiso existe
    query_permiso = select(Permission).filter(col(Permission.id) == permission_id)
    permission = db.exec(query_permiso).first()
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permiso no encontrado",
        )

    # Verificar que el permiso esté asignado al rol
    query_role_permission = select(RolePermission).filter(
        col(RolePermission.role_id) == role_id,
        col(RolePermission.permission_id) == permission_id,
    )
    role_permission = db.exec(query_role_permission).first()

    if not role_permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="El permiso no está asignado al rol",
        )

    # Eliminar la asignación
    db.delete(role_permission)
    db.commit()

    # Registrar en auditoría
    if current_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no Encontrado")
    auditoria_service = AuditoriaService(db)
    auditoria_service.registrar_accion(
        usuario_id=current_user.id,
        tipo_accion=TipoAccion.ELIMINAR,
        modulo="Auth",
        entidad="RolePermission",
        detalles={
            "role_id": role_id,
            "role_name": role.name,
            "permission_id": permission_id,
            "permission_code": permission.code,
        },
        descripcion=f"Eliminación de permiso {permission.code} del rol {role.name}",
        resultado=True,
    )

    return StandardResponse(
        status="success",
        message="Permiso eliminado exitosamente",
        data=None,
    )


@router.get(
    "/permissions",
    response_model=StandardResponse[List[PermissionRead]],
    dependencies=[Depends(has_permission("permission:read"))],
)
async def get_permissions(
    db: SessionDep,
    module: Optional[str] = Query(None, description="Filtrar por módulo"),
):
    """
    Obtiene todos los permisos disponibles en el sistema.

    Requiere permiso: **permission:read**
    """
    query = select(Permission)

    if module:
        query = query.filter(col(Permission.module) == module)

    permissions = db.exec(query).all()

    return StandardResponse(
        status="success",
        message="Permisos recuperados exitosamente",
        data=[
            PermissionRead(
                id=permission.id,
                code=permission.code,
                name=permission.name,
                description=permission.description,
                module=permission.module,
            )
            for permission in permissions
        ],
    )
