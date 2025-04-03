from typing import Optional, Type

from sqlmodel import col, or_, select

from app.core.enums import UserStatus
from app.models.auth.user_model import User
from app.repositories.base_repository import BaseRepository


class UserRepository(BaseRepository[User]):
    """Repositorio para operaciones de acceso a datos de usuarios."""

    def _get_model_class(self) -> Type[User]:
        return User

    def get_by_username(self, username: str) -> Optional[User]:
        """
        Obtiene un usuario por su nombre de usuario.

        Args:
            username: Nombre de usuario a buscar

        Returns:
            Usuario encontrado o None
        """
        query = select(User).where(User.username == username, col(User.estado_audit).is_(True))
        return self.db.exec(query).first()

    def get_by_email(self, email: str) -> Optional[User]:
        """
        Obtiene un usuario por su correo electrónico.

        Args:
            email: Correo electrónico a buscar

        Returns:
            Usuario encontrado o None
        """
        query = select(User).where(User.email == email, col(User.estado_audit).is_(True))
        return self.db.exec(query).first()

    def get_by_username_or_email(self, username_or_email: str) -> Optional[User]:
        """
        Obtiene un usuario por su nombre de usuario o correo electrónico.

        Args:
            username_or_email: Nombre de usuario o correo electrónico a buscar

        Returns:
            Usuario encontrado o None
        """
        query = select(User).where(
            or_(User.username == username_or_email, User.email == username_or_email),
            col(User.estado_audit).is_(True),
        )
        return self.db.exec(query).first()

    def is_active(self, user_id: int) -> bool:
        """
        Verifica si un usuario está activo.

        Args:
            user_id: ID del usuario

        Returns:
            True si el usuario está activo, False si no
        """
        query = select(User).where(
            User.id == user_id,
            col(User.is_active).is_(True),
            User.status == UserStatus.ACTIVE,
            col(User.estado_audit).is_(True),
        )
        return self.db.exec(query).first() is not None

    def is_locked(self, user_id: int) -> bool:
        """
        Verifica si un usuario está bloqueado.

        Args:
            user_id: ID del usuario

        Returns:
            True si el usuario está bloqueado, False si no
        """
        query = select(User).where(
            User.id == user_id, User.status == UserStatus.LOCKED, col(User.estado_audit).is_(True)
        )
        return self.db.exec(query).first() is not None

    def search_users(
        self,
        skip: int = 0,
        limit: int = 100,
        search_term: Optional[str] = None,
        is_active: Optional[bool] = None,
        status: Optional[str] = None,
    ):
        """
        Busca usuarios según criterios con paginación.

        Args:
            skip: Número de registros a omitir
            limit: Límite de registros a devolver
            search_term: Término de búsqueda para username, email o nombre completo
            is_active: Filtra por estado activo/inactivo
            status: Filtra por status específico

        Returns:
            Lista de usuarios y conteo total
        """
        query = select(User).where(col(User.estado_audit).is_(True))

        # Aplicar filtros
        if search_term:
            search_pattern = f"%{search_term}%"
            query = query.where(
                or_(
                    col(User.username).ilike(search_pattern),
                    col(User.email).ilike(search_pattern),
                    col(User.full_name).ilike(search_pattern),
                )
            )

        if is_active is not None:
            query = query.where(User.is_active == is_active)

        if status:
            query = query.where(User.status == status)

        # Contar total de registros
        count_query = select(User).where(query.whereclause or True)
        total = len(self.db.exec(count_query).all())

        # Aplicar paginación
        query = query.offset(skip).limit(limit)

        # Ejecutar consulta
        users = list(self.db.exec(query).all())

        return users, total
