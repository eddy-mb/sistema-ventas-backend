from typing import List, Optional, Type

from sqlmodel import col, select

from app.models.auth.role_model import Permission, Role, RolePermission
from app.repositories.base_repository import BaseRepository


class RoleRepository(BaseRepository[Role]):
    """Repositorio para operaciones de acceso a datos de roles."""

    def _get_model_class(self) -> Type[Role]:
        return Role

    def get_by_name(self, name: str) -> Optional[Role]:
        """
        Busca un rol por su nombre.

        Args:
            name: Nombre del rol a buscar

        Returns:
            Rol encontrado o None
        """
        query = select(Role).where(Role.name == name, col(Role.estado_audit).is_(True))
        return self.db.exec(query).first()

    def get_role_permissions(self, role_id: int) -> List[Permission]:
        """
        Obtiene todos los permisos asignados a un rol.

        Args:
            role_id: ID del rol

        Returns:
            Lista de permisos
        """
        query = (
            select(Permission)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .where(RolePermission.role_id == role_id)
        )
        return list(self.db.exec(query).all())


class PermissionRepository(BaseRepository[Permission]):
    """Repositorio para operaciones de acceso a datos de permisos."""

    def _get_model_class(self) -> Type[Permission]:
        return Permission

    def get_by_code(self, code: str) -> Optional[Permission]:
        """
        Busca un permiso por su código.

        Args:
            code: Código del permiso a buscar

        Returns:
            Permiso encontrado o None
        """
        query = select(Permission).where(Permission.code == code)
        return self.db.exec(query).first()

    def get_by_module(self, module: str) -> List[Permission]:
        """
        Obtiene todos los permisos de un módulo específico.

        Args:
            module: Nombre del módulo

        Returns:
            Lista de permisos del módulo
        """
        query = select(Permission).where(Permission.module == module)
        return list(self.db.exec(query).all())
