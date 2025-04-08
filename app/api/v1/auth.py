from typing import Annotated, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, status

from app.core.enums import UserStatus
from app.dependencies.auth import get_current_active_user, has_permission
from app.dependencies.db import SessionDep
from app.models.auth.role_model import RoleRead
from app.models.auth.user_model import User, UserCreate, UserRead, UserUpdate
from app.schemas.auth.auth_schema import LoginData
from app.schemas.common_schema import StandardResponse
from app.services.auth_service import AuthService
from app.utils.pagination import PagedResponse, PaginationParams, paginate_results

router = APIRouter(prefix="/auth", tags=["Authentication"])


class Token(StandardResponse):
    """Esquema de respuesta para tokens."""

    data: dict


@router.post("/login", response_model=Token)
async def login(db: SessionDep, login_data: LoginData):
    """
    Obtiene un token de acceso utilizando credenciales de usuario.

    - **username**: Nombre de usuario o correo electrónico
    - **password**: Contraseña

    Returns:
        Token de acceso y de refresco
    """
    auth_service = AuthService(db)
    user, access_token, refresh_token = auth_service.authenticate_user(
        login_data.email, login_data.password
    )

    return Token(
        status="success",
        message="Inicio de sesión exitoso",
        data={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "username": user.username,
                "full_name": user.full_name,
                "email": user.email,
                "is_active": user.is_active,
                "is_superuser": user.is_superuser,
            },
        },
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    db: SessionDep,
    refresh_token: str = Body(..., embed=True),
):
    """
    Obtiene un nuevo token de acceso utilizando un token de refresco.

    - **refresh_token**: Token de refresco

    Returns:
        Nuevo token de acceso
    """
    # TODO: Implementar la lógica de refresco de token
    # Esta funcionalidad se implementará en una fase posterior
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Esta funcionalidad aún no está implementada",
    )


@router.get("/me", response_model=StandardResponse[UserRead])
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    """
    Obtiene información del usuario autenticado.
    """
    return StandardResponse(
        status="success",
        message="Información del usuario recuperada exitosamente",
        data=current_user,
    )


@router.get("/me/roles", response_model=StandardResponse[List[RoleRead]])
async def read_users_me_roles(
    db: SessionDep,
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    """
    Obtiene los roles del usuario autenticado.
    """
    if current_user.id is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Usuario sin ID válido")

    auth_service = AuthService(db)
    roles = auth_service.get_user_roles(current_user.id)

    return StandardResponse(
        status="success",
        message="Roles del usuario recuperados exitosamente",
        data=[
            RoleRead(
                id=role.id,
                name=role.name,
                description=role.description,
            )
            for role in roles
        ],
    )


@router.get("/me/permissions", response_model=StandardResponse[List[str]])
async def read_users_me_permissions(
    db: SessionDep,
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    """
    Obtiene los permisos del usuario autenticado.
    """
    if current_user.id is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Usuario sin ID válido")
    auth_service = AuthService(db)
    permissions = auth_service.get_user_permissions(current_user.id)

    return StandardResponse(
        status="success",
        message="Permisos del usuario recuperados exitosamente",
        data=permissions,
    )


@router.post(
    "/users",
    response_model=StandardResponse[UserRead],
    dependencies=[Depends(has_permission("user:create"))],
    status_code=status.HTTP_201_CREATED,
)
async def create_user(
    user_data: UserCreate,
    db: SessionDep,
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    """
    Crea un nuevo usuario.

    Requiere permiso: **user:create**
    """
    auth_service = AuthService(db)
    user = auth_service.create_user(user_data, current_user.id)

    return StandardResponse(
        status="success",
        message="Usuario creado exitosamente",
        data=user,
    )


@router.get(
    "/users",
    response_model=StandardResponse[PagedResponse[UserRead]],
    dependencies=[Depends(has_permission("user:read"))],
)
async def get_users(
    db: SessionDep,
    pagination: PaginationParams = Depends(),
    search: Optional[str] = Query(None, description="Término de búsqueda"),
    is_active: Optional[bool] = Query(None, description="Filtrar por estado activo"),
    status: Optional[UserStatus] = Query(None, description="Filtrar por estado específico"),
):
    """
    Obtiene una lista paginada de usuarios.

    Requiere permiso: **user:read**
    """
    user_repository = AuthService(db).user_repository
    users, total = user_repository.search_users(
        skip=pagination.skip,
        limit=pagination.limit,
        search_term=search,
        is_active=is_active,
        status=status.value if status else None,
    )

    # Crear respuesta paginada
    paged_response = paginate_results(users, total, pagination)

    return StandardResponse(
        status="success",
        message="Usuarios recuperados exitosamente",
        data=paged_response,
    )


@router.get(
    "/users/{user_id}",
    response_model=StandardResponse[UserRead],
    dependencies=[Depends(has_permission("user:read"))],
)
async def get_user(
    db: SessionDep,
    user_id: int = Path(..., gt=0),
):
    """
    Obtiene información de un usuario específico.

    Requiere permiso: **user:read**
    """
    user_repository = AuthService(db).user_repository
    user = user_repository.get_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )

    return StandardResponse(
        status="success",
        message="Usuario recuperado exitosamente",
        data=user,
    )


@router.put(
    "/users/{user_id}",
    response_model=StandardResponse[UserRead],
    dependencies=[Depends(has_permission("user:update"))],
)
async def update_user(
    user_data: UserUpdate,
    db: SessionDep,
    user_id: int = Path(..., gt=0),
    current_user: Annotated[Optional[User], Depends(get_current_active_user)] = None,
):
    """
    Actualiza información de un usuario.

    Requiere permiso: **user:update**
    """

    if current_user is None:
        raise HTTPException(status_code=401, detail="Usuario no autenticado")

    auth_service = AuthService(db)
    user = auth_service.update_user(user_id, user_data, current_user.id)

    return StandardResponse(
        status="success",
        message="Usuario actualizado exitosamente",
        data=user,
    )


@router.delete(
    "/users/{user_id}",
    response_model=StandardResponse[None],
    dependencies=[Depends(has_permission("user:delete"))],
)
async def delete_user(
    db: SessionDep,
    user_id: int = Path(..., gt=0),
    current_user: Annotated[User | None, Depends(get_current_active_user)] = None,
):
    """
    Elimina un usuario (desactivación lógica).

    Requiere permiso: **user:delete**
    """
    # Obtener el usuario a eliminar
    if current_user is None:
        raise HTTPException(status_code=401, detail="Usuario no autenticado")

    user_repository = AuthService(db).user_repository
    user = user_repository.get_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )

    # No permitir eliminar superusuarios a menos que sea otro superusuario
    if user.is_superuser and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para eliminar superusuarios",
        )

    # No permitir que el usuario se elimine a sí mismo
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No puedes eliminar tu propio usuario",
        )

    # Eliminar usuario (eliminación lógica)
    result = user_repository.delete(user_id, str(current_user.id))

    if not result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al eliminar el usuario",
        )

    return StandardResponse(
        status="success",
        message="Usuario eliminado exitosamente",
        data=None,
    )


@router.post(
    "/users/{user_id}/change-password",
    response_model=StandardResponse[None],
    dependencies=[Depends(has_permission("user:update"))],
)
async def change_user_password(
    db: SessionDep,
    user_id: int = Path(..., gt=0),
    current_password: str = Body(...),
    new_password: str = Body(...),
    current_user: Annotated[User | None, Depends(get_current_active_user)] = None,
):
    """
    Cambia la contraseña de un usuario.

    - Si el usuario actual es el mismo que se está modificando, se requiere la contraseña actual
    - Si el usuario actual es un administrador, puede cambiar la contraseña sin la contraseña actual

    Requiere permiso: **user:update**
    """
    if current_user is None:
        raise HTTPException(status_code=401, detail="Usuario no autenticado")
    auth_service = AuthService(db)

    # Verificar si el usuario actual tiene permiso para cambiar la contraseña sin verificación
    skip_current_password = current_user.is_superuser and user_id != current_user.id

    # Cambiar contraseña
    auth_service.change_user_password(
        user_id,
        "" if skip_current_password else current_password,
        new_password,
        current_user.id,
    )

    return StandardResponse(
        status="success",
        message="Contraseña cambiada exitosamente",
        data=None,
    )


@router.post(
    "/users/{user_id}/roles/{role_id}",
    response_model=StandardResponse[None],
    dependencies=[Depends(has_permission("user:manage_roles"))],
)
async def assign_role_to_user(
    db: SessionDep,
    user_id: int = Path(..., gt=0),
    role_id: int = Path(..., gt=0),
    current_user: Annotated[User | None, Depends(get_current_active_user)] = None,
):
    """
    Asigna un rol a un usuario.

    Requiere permiso: **user:manage_roles**
    """
    if current_user is None:
        raise HTTPException(status_code=401, detail="Usuario no autenticado")

    auth_service = AuthService(db)
    auth_service.assign_role_to_user(user_id, role_id, current_user.id)

    return StandardResponse(
        status="success",
        message="Rol asignado exitosamente",
        data=None,
    )


@router.delete(
    "/users/{user_id}/roles/{role_id}",
    response_model=StandardResponse[None],
    dependencies=[Depends(has_permission("user:manage_roles"))],
)
async def remove_role_from_user(
    db: SessionDep,
    user_id: int = Path(..., gt=0),
    role_id: int = Path(..., gt=0),
    current_user: Annotated[User | None, Depends(get_current_active_user)] = None,
):
    """
    Elimina un rol de un usuario.

    Requiere permiso: **user:manage_roles**
    """
    if current_user is None:
        raise HTTPException(status_code=401, detail="Usuario no autenticado")

    auth_service = AuthService(db)
    auth_service.remove_role_from_user(user_id, role_id, current_user.id)

    return StandardResponse(
        status="success",
        message="Rol eliminado exitosamente",
        data=None,
    )
