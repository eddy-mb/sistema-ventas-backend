from datetime import datetime, timezone
from typing import List, Optional, Tuple

from fastapi import HTTPException, status
from sqlmodel import Session, col, select

from app.core.config import get_settings
from app.core.enums import EstadoUsuario
from app.models.auth.role_model import Permission, Role, RolePermission, UserRole
from app.models.auth.user_model import User, UserCreate, UserUpdate
from app.repositories.auth.user_repository import UserRepository
from app.services.auditoria_service import AuditoriaService, TipoAccion
from app.utils.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
)

settings = get_settings()


class AuthService:
    """Servicio para manejar autenticación y autorización"""

    def __init__(self, db: Session):
        self.db = db
        self.user_repository = UserRepository(db)
        self.auditoria_service = AuditoriaService(db)

    def authenticate_user(self, username: str, password: str) -> Tuple[User, str, str]:
        """
        Autentica a un usuario y retorna tokens si las credenciales son válidas.

        Args:
            username: Nombre de usuario o email
            password: Contraseña

        Returns:
            Tupla con (usuario, token_acceso, token_refresco)

        Raises:
            HTTPException: Si las credenciales son inválidas o el usuario está bloqueado
        """
        # Buscar usuario por nombre de usuario o email
        user = self.user_repository.get_by_username_or_email(username)

        if not user:
            # Registrar intento fallido en auditoría
            self.auditoria_service.registrar_accion(
                usuario_id=None,
                tipo_accion=TipoAccion.INICIAR_SESION,
                modulo="Auth",
                entidad="User",
                detalles={"username": username, "status": "failed", "reason": "user_not_found"},
                descripcion="Intento de inicio de sesión fallido - Usuario no encontrado",
                resultado=False,
            )
            # Usar el mismo mensaje para no dar pistas sobre la existencia del usuario
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales incorrectas",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verificar estado del usuario
        if user.status != EstadoUsuario.ACTIVO:
            # Registrar intento fallido en auditoría
            self.auditoria_service.registrar_accion(
                usuario_id=user.id,
                tipo_accion=TipoAccion.INICIAR_SESION,
                modulo="Auth",
                entidad="User",
                entidad_id=user.id,
                detalles={
                    "username": username,
                    "status": "failed",
                    "reason": f"user_status_{user.status}",
                },
                descripcion=f"Intento de inicio de sesión fallido - Usuario {user.status.value}",
                resultado=False,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario inactivo o bloqueado",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verificar contraseña
        if not verify_password(password, user.hashed_password):
            # Incrementar contador de intentos fallidos
            user.failed_login_attempts += 1

            # Bloquear cuenta si se supera el límite de intentos
            if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
                user.status = EstadoUsuario.BLOQUEADO

            self.db.add(user)
            self.db.commit()

            # Registrar intento fallido en auditoría
            self.auditoria_service.registrar_accion(
                usuario_id=user.id,
                tipo_accion=TipoAccion.INICIAR_SESION,
                modulo="Auth",
                entidad="User",
                entidad_id=user.id,
                detalles={
                    "username": username,
                    "status": "failed",
                    "reason": "invalid_password",
                    "failed_attempts": user.failed_login_attempts,
                    "user_locked": user.status == EstadoUsuario.BLOQUEADO,
                },
                descripcion="Intento de inicio de sesión fallido - Contraseña incorrecta",
                resultado=False,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales incorrectas",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Autenticación exitosa - Reiniciar contador de intentos y actualizar último acceso
        user.failed_login_attempts = 0
        user.last_login = datetime.now(timezone.utc)
        self.db.add(user)
        self.db.commit()

        # Obtener permisos del usuario para incluir en el token
        user_permissions = self.get_user_permissions(user.id)

        # Generar tokens
        access_token = create_access_token(
            subject=user.id,
            scopes=user_permissions,
        )
        refresh_token = create_refresh_token(subject=user.id)

        # Registrar inicio de sesión exitoso en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=user.id,
            tipo_accion=TipoAccion.INICIAR_SESION,
            modulo="Auth",
            entidad="User",
            entidad_id=user.id,
            detalles={"username": username, "status": "success"},
            descripcion="Inicio de sesión exitoso",
            resultado=True,
        )

        return user, access_token, refresh_token

    def create_user(self, user_data: UserCreate, created_by: Optional[int] = None) -> User:
        """
        Crea un nuevo usuario en el sistema.

        Args:
            user_data: Datos del usuario a crear
            created_by: ID del usuario que crea el nuevo usuario

        Returns:
            Usuario creado

        Raises:
            HTTPException: Si el nombre de usuario o email ya existen
        """
        # Verificar si el usuario ya existe
        if self.user_repository.get_by_username(user_data.username):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El nombre de usuario ya está en uso",
            )

        if self.user_repository.get_by_email(user_data.email):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El correo electrónico ya está registrado",
            )

        # Crear el usuario con la contraseña hasheada
        user_dict = user_data.model_dump()
        hashed_password = get_password_hash(user_dict.pop("password"))

        user = self.user_repository.create(
            {
                **user_dict,
                "hashed_password": hashed_password,
                "password_change_date": datetime.now(timezone.utc),
            },
            str(created_by) if created_by else "system",
        )

        # Registrar creación en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=created_by,
            tipo_accion=TipoAccion.CREAR,
            modulo="Auth",
            entidad="User",
            entidad_id=user.id,
            detalles={"username": user.username, "email": user.email},
            descripcion=f"Creación de usuario: {user.username}",
            resultado=True,
        )

        return user

    def update_user(
        self, user_id: int, user_data: UserUpdate, updated_by: Optional[int] = None
    ) -> User:
        """
        Actualiza un usuario existente.

        Args:
            user_id: ID del usuario a actualizar
            user_data: Datos actualizados del usuario
            updated_by: ID del usuario que realiza la actualización

        Returns:
            Usuario actualizado

        Raises:
            HTTPException: Si el usuario no existe o los datos son inválidos
        """
        # Verificar que el usuario existe
        user = self.user_repository.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )

        # Verificar que el nombre de usuario y email no estén en uso
        if user_data.username and user_data.username != user.username:
            if self.user_repository.get_by_username(user_data.username):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="El nombre de usuario ya está en uso",
                )

        if user_data.email and user_data.email != user.email:
            if self.user_repository.get_by_email(user_data.email):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="El correo electrónico ya está registrado",
                )

        # Actualizar el usuario
        update_data = user_data.model_dump(exclude_unset=True)
        updated_user = self.user_repository.update(
            user_id, update_data, str(updated_by) if updated_by else "system"
        )

        # Registrar actualización en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=updated_by,
            tipo_accion=TipoAccion.ACTUALIZAR,
            modulo="Auth",
            entidad="User",
            entidad_id=user_id,
            detalles={"updated_fields": update_data},
            descripcion=f"Actualización de usuario ID: {user_id}",
            resultado=True,
        )

        return updated_user

    def change_user_password(
        self, user_id: int, current_password: str, new_password: str, actor_id: Optional[int] = None
    ) -> bool:
        """
        Cambia la contraseña de un usuario.

        Args:
            user_id: ID del usuario
            current_password: Contraseña actual
            new_password: Nueva contraseña
            actor_id: ID del usuario que realiza el cambio (None si es el propio usuario)

        Returns:
            True si se cambió correctamente

        Raises:
            HTTPException: Si el usuario no existe o la contraseña actual es incorrecta
        """
        # Verificar que el usuario existe
        user = self.user_repository.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )

        # Si el cambio lo hace el propio usuario, verificar la contraseña actual
        # (a menos que sea un administrador)
        if not actor_id or actor_id == user_id:
            if not verify_password(current_password, user.hashed_password):
                # Registrar intento fallido en auditoría
                self.auditoria_service.registrar_accion(
                    usuario_id=user_id,
                    tipo_accion=TipoAccion.ACTUALIZAR,
                    modulo="Auth",
                    entidad="User",
                    entidad_id=user_id,
                    detalles={"action": "change_password", "status": "failed"},
                    descripcion="Cambio de contraseña fallido - Contraseña actual incorrecta",
                    resultado=False,
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Contraseña actual incorrecta",
                )

        # Actualizar contraseña
        user.hashed_password = get_password_hash(new_password)
        user.password_change_date = datetime.now(timezone.utc)
        user.status = (
            EstadoUsuario.ACTIVO
        )  # Desbloquear si estaba bloqueado por contraseña expirada

        self.db.add(user)
        self.db.commit()

        # Registrar cambio en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=actor_id if actor_id else user_id,
            tipo_accion=TipoAccion.ACTUALIZAR,
            modulo="Auth",
            entidad="User",
            entidad_id=user_id,
            detalles={"action": "change_password", "status": "success"},
            descripcion="Cambio de contraseña exitoso",
            resultado=True,
        )

        return True

    def assign_role_to_user(
        self, user_id: int, role_id: int, actor_id: Optional[int] = None
    ) -> bool:
        """
        Asigna un rol a un usuario.

        Args:
            user_id: ID del usuario
            role_id: ID del rol
            actor_id: ID del usuario que realiza la asignación

        Returns:
            True si se asignó correctamente

        Raises:
            HTTPException: Si el usuario o rol no existen o el rol ya está asignado
        """
        # Verificar que el usuario existe
        user = self.user_repository.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )

        # Verificar que el rol existe
        role = self.db.exec(select(Role).where(Role.id == role_id)).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Rol no encontrado",
            )

        # Verificar que el rol no esté ya asignado
        existing_user_role = self.db.exec(
            select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
        ).first()

        if existing_user_role:
            # No es un error, simplemente notificamos que ya estaba asignado
            return True

        # Asignar el rol
        user_role = UserRole(user_id=user_id, role_id=role_id)
        self.db.add(user_role)
        self.db.commit()

        # Registrar asignación en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=actor_id,
            tipo_accion=TipoAccion.ACTUALIZAR,
            modulo="Auth",
            entidad="UserRole",
            detalles={"user_id": user_id, "role_id": role_id, "action": "assign_role"},
            descripcion=f"Asignación de rol '{role.name}' al usuario ID: {user_id}",
            resultado=True,
        )

        return True

    def remove_role_from_user(
        self, user_id: int, role_id: int, actor_id: Optional[int] = None
    ) -> bool:
        """
        Elimina un rol de un usuario.

        Args:
            user_id: ID del usuario
            role_id: ID del rol
            actor_id: ID del usuario que realiza la eliminación

        Returns:
            True si se eliminó correctamente

        Raises:
            HTTPException: Si el usuario o rol no existen o el rol no está asignado
        """
        # Verificar que el usuario existe
        user = self.user_repository.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )

        # Verificar que el rol existe
        role = self.db.exec(select(Role).where(Role.id == role_id)).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Rol no encontrado",
            )

        # Buscar la asignación del rol
        user_role = self.db.exec(
            select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
        ).first()

        if not user_role:
            # No es un error, simplemente notificamos que no estaba asignado
            return True

        # Eliminar la asignación
        self.db.delete(user_role)
        self.db.commit()

        # Registrar eliminación en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=actor_id,
            tipo_accion=TipoAccion.ELIMINAR,
            modulo="Auth",
            entidad="UserRole",
            detalles={"user_id": user_id, "role_id": role_id, "action": "remove_role"},
            descripcion=f"Eliminación de rol '{role.name}' del usuario ID: {user_id}",
            resultado=True,
        )

        return True

    def get_user_roles(self, user_id: int) -> List[Role]:
        """
        Obtiene los roles asignados a un usuario.

        Args:
            user_id: ID del usuario

        Returns:
            Lista de roles asignados al usuario

        Raises:
            HTTPException: Si el usuario no existe
        """
        # Verificar que el usuario existe
        user = self.user_repository.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )

        # Obtener roles
        query = select(Role).join(UserRole).where(UserRole.user_id == user_id)
        roles = self.db.exec(query).all()

        return roles

    def get_user_permissions(self, user_id: int) -> List[str]:
        """
        Obtiene los códigos de permisos asignados a un usuario a través de sus roles.

        Args:
            user_id: ID del usuario

        Returns:
            Lista de códigos de permisos
        """
        query = (
            select(Permission)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .join(Role, Role.id == RolePermission.role_id)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
            .distinct()
        )
        permission_codes = [permission.code for permission in self.db.exec(query).all()]

        # Añadir automáticamente el permiso de autenticación para todos los usuarios activos
        if permission_codes or self.user_repository.is_active(user_id):
            permission_codes.append("auth:authenticated")

        # Para superusuarios, añadir permiso de superadmin
        user = self.user_repository.get_by_id(user_id)
        if user and user.is_superuser:
            permission_codes.append("admin:superuser")

        return permission_codes

    def has_permission(self, user_id: int, permission_code: str) -> bool:
        """
        Verifica si un usuario tiene un permiso específico.

        Args:
            user_id: ID del usuario
            permission_code: Código del permiso a verificar

        Returns:
            True si el usuario tiene el permiso, False en caso contrario
        """
        permissions = self.get_user_permissions(user_id)

        # Verificar superusuario primero (tiene todos los permisos)
        if "admin:superuser" in permissions:
            return True

        return permission_code in permissions

    def create_role(
        self, name: str, description: Optional[str] = None, actor_id: Optional[int] = None
    ) -> Role:
        """
        Crea un nuevo rol en el sistema.

        Args:
            name: Nombre del rol
            description: Descripción del rol
            actor_id: ID del usuario que crea el rol

        Returns:
            Rol creado

        Raises:
            HTTPException: Si ya existe un rol con el mismo nombre
        """
        # Verificar si ya existe un rol con el mismo nombre
        existing_role = self.db.exec(select(Role).where(Role.name == name)).first()
        if existing_role:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Ya existe un rol con ese nombre",
            )

        # Crear el rol
        role = Role(name=name, description=description, is_system_role=False)

        self.db.add(role)
        self.db.commit()
        self.db.refresh(role)

        # Registrar creación en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=actor_id,
            tipo_accion=TipoAccion.CREAR,
            modulo="Auth",
            entidad="Role",
            entidad_id=role.id,
            detalles={"name": name, "description": description},
            descripcion=f"Creación de rol: {name}",
            resultado=True,
        )

        return role

    def assign_permission_to_role(
        self, role_id: int, permission_id: int, actor_id: Optional[int] = None
    ) -> bool:
        """
        Asigna un permiso a un rol.

        Args:
            role_id: ID del rol
            permission_id: ID del permiso
            actor_id: ID del usuario que realiza la asignación

        Returns:
            True si se asignó correctamente

        Raises:
            HTTPException: Si el rol o permiso no existen o el permiso ya está asignado
        """
        # Verificar que el rol existe
        role = self.db.exec(select(Role).where(Role.id == role_id)).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Rol no encontrado",
            )

        # Verificar que el permiso existe
        permission = self.db.exec(select(Permission).where(Permission.id == permission_id)).first()
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permiso no encontrado",
            )

        # Verificar que el permiso no esté ya asignado
        existing_role_permission = self.db.exec(
            select(RolePermission).where(
                RolePermission.role_id == role_id, RolePermission.permission_id == permission_id
            )
        ).first()

        if existing_role_permission:
            # No es un error, simplemente notificamos que ya estaba asignado
            return True

        # Asignar el permiso
        role_permission = RolePermission(role_id=role_id, permission_id=permission_id)
        self.db.add(role_permission)
        self.db.commit()

        # Registrar asignación en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=actor_id,
            tipo_accion=TipoAccion.ACTUALIZAR,
            modulo="Auth",
            entidad="RolePermission",
            detalles={
                "role_id": role_id,
                "permission_id": permission_id,
                "action": "assign_permission",
            },
            descripcion=f"Asignación de permiso '{permission.code}' al rol '{role.name}'",
            resultado=True,
        )

        return True

    def remove_permission_from_role(
        self, role_id: int, permission_id: int, actor_id: Optional[int] = None
    ) -> bool:
        """
        Elimina un permiso de un rol.

        Args:
            role_id: ID del rol
            permission_id: ID del permiso
            actor_id: ID del usuario que realiza la eliminación

        Returns:
            True si se eliminó correctamente

        Raises:
            HTTPException: Si el rol o permiso no existen o el permiso no está asignado
        """
        # Verificar que el rol existe
        role = self.db.exec(select(Role).where(Role.id == role_id)).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Rol no encontrado",
            )

        # Verificar que el permiso existe
        permission = self.db.exec(select(Permission).where(Permission.id == permission_id)).first()
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permiso no encontrado",
            )

        # Buscar la asignación del permiso
        role_permission = self.db.exec(
            select(RolePermission).where(
                RolePermission.role_id == role_id, RolePermission.permission_id == permission_id
            )
        ).first()

        if not role_permission:
            # No es un error, simplemente notificamos que no estaba asignado
            return True

        # Eliminar la asignación
        self.db.delete(role_permission)
        self.db.commit()

        # Registrar eliminación en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=actor_id,
            tipo_accion=TipoAccion.ELIMINAR,
            modulo="Auth",
            entidad="RolePermission",
            detalles={
                "role_id": role_id,
                "permission_id": permission_id,
                "action": "remove_permission",
            },
            descripcion=f"Eliminación de permiso '{permission.code}' del rol '{role.name}'",
            resultado=True,
        )

        return True

    def get_all_permissions(self) -> List[Permission]:
        """
        Obtiene todos los permisos del sistema.

        Returns:
            Lista de permisos
        """
        query = select(Permission).order_by(Permission.module, Permission.code)
        permissions = self.db.exec(query).all()

        return permissions

    def get_all_roles(self) -> List[Role]:
        """
        Obtiene todos los roles del sistema.

        Returns:
            Lista de roles
        """
        query = select(Role).order_by(Role.name)
        roles = self.db.exec(query).all()

        return roles

    def deactivate_user(self, user_id: int, actor_id: Optional[int] = None) -> bool:
        """
        Desactiva un usuario del sistema.

        Args:
            user_id: ID del usuario a desactivar
            actor_id: ID del usuario que realiza la desactivación

        Returns:
            True si se desactivó correctamente

        Raises:
            HTTPException: Si el usuario no existe o es el último superusuario
        """
        # Verificar que el usuario existe
        user = self.user_repository.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )

        # Si es superusuario, verificar que no sea el último
        if user.is_superuser:
            superusers_count = self.db.exec(
                select(User).where(col(User.is_superuser).is_(True), col(User.is_active).is_(True))
            ).count()

            if superusers_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No se puede desactivar el último superusuario",
                )

        # Desactivar usuario
        user.is_active = False
        user.status = EstadoUsuario.INACTIVO

        self.db.add(user)
        self.db.commit()

        # Registrar desactivación en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=actor_id,
            tipo_accion=TipoAccion.ACTUALIZAR,
            modulo="Auth",
            entidad="User",
            entidad_id=user_id,
            detalles={"action": "deactivate_user"},
            descripcion=f"Desactivación de usuario ID: {user_id}",
            resultado=True,
        )

        return True

    def activate_user(self, user_id: int, actor_id: Optional[int] = None) -> bool:
        """
        Activa un usuario previamente desactivado.

        Args:
            user_id: ID del usuario a activar
            actor_id: ID del usuario que realiza la activación

        Returns:
            True si se activó correctamente

        Raises:
            HTTPException: Si el usuario no existe
        """
        # Verificar que el usuario existe
        user = self.user_repository.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )

        # Activar usuario
        user.is_active = True
        if user.status == EstadoUsuario.INACTIVO:
            user.status = EstadoUsuario.ACTIVO

        self.db.add(user)
        self.db.commit()

        # Registrar activación en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=actor_id,
            tipo_accion=TipoAccion.ACTUALIZAR,
            modulo="Auth",
            entidad="User",
            entidad_id=user_id,
            detalles={"action": "activate_user"},
            descripcion=f"Activación de usuario ID: {user_id}",
            resultado=True,
        )

        return True

    def unlock_user(self, user_id: int, actor_id: Optional[int] = None) -> bool:
        """
        Desbloquea un usuario previamente bloqueado.

        Args:
            user_id: ID del usuario a desbloquear
            actor_id: ID del usuario que realiza el desbloqueo

        Returns:
            True si se desbloqueó correctamente

        Raises:
            HTTPException: Si el usuario no existe o no está bloqueado
        """
        # Verificar que el usuario existe
        user = self.user_repository.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )

        # Verificar que el usuario está bloqueado
        if user.status != EstadoUsuario.BLOQUEADO:
            return True  # No es un error, simplemente no hacemos nada

        # Desbloquear usuario
        user.status = EstadoUsuario.ACTIVO
        user.failed_login_attempts = 0

        self.db.add(user)
        self.db.commit()

        # Registrar desbloqueo en auditoría
        self.auditoria_service.registrar_accion(
            usuario_id=actor_id,
            tipo_accion=TipoAccion.ACTUALIZAR,
            modulo="Auth",
            entidad="User",
            entidad_id=user_id,
            detalles={"action": "unlock_user"},
            descripcion=f"Desbloqueo de usuario ID: {user_id}",
            resultado=True,
        )

        return True
