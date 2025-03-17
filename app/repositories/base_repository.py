from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar

from sqlmodel import Session, col, select

from app.models.auditoria.base_model import BaseModel

T = TypeVar("T", bound=BaseModel)


class BaseRepository(Generic[T], ABC):
    """
    Repositorio base abstracto que define operaciones estándar de
    acceso a datos.
    Las implementaciones deben manejar los detalles específicos de trabajar
    con una entidad particular.
    """

    def __init__(self, db: Session):
        self.db = db
        self.model_class: Type[T] = self._get_model_class()

    @abstractmethod
    def _get_model_class(self) -> Type[T]:
        """Retorna la clase del modelo con la que trabaja este repositorio."""
        pass

    def create(self, data: Dict[str, Any], usuario: str = "sistema") -> T:
        """Crea un nuevo registro con información de auditoría."""
        obj = self.model_class(**data)
        obj.usuario_creacion = usuario
        obj.fecha_creacion = datetime.now(timezone.utc)
        self.db.add(obj)
        self.db.commit()
        self.db.refresh(obj)
        return obj

    def update(self, id: int, data: Dict[str, Any], usuario: str = "sistema") -> Optional[T]:
        """Actualiza un registro existente con información de auditoría."""
        obj = self.get_by_id(id)
        if not obj:
            return None

        for key, value in data.items():
            setattr(obj, key, value)

        obj.usuario_modificacion = usuario
        obj.fecha_modificacion = datetime.now(timezone.utc)

        self.db.add(obj)
        self.db.commit()
        self.db.refresh(obj)
        return obj

    def get_by_id(self, id: int) -> Optional[T]:
        """Recupera un registro por su ID."""
        query = select(self.model_class).where(
            self.model_class.id == id, col(self.model_class.estado_audit).is_(True)
        )
        return self.db.exec(query).first()

    def get_all(self) -> List[T]:
        """Recupera todos los registros activos."""
        query = select(self.model_class).where(col(self.model_class.estado_audit).is_(True))
        return list(self.db.exec(query).all())

    def delete(self, id: int, usuario: str = "sistema") -> bool:
        """Elimina lógicamente un registro (cambia el estado)."""
        obj = self.get_by_id(id)
        if not obj:
            return False

        obj.estado_audit = False
        obj.usuario_modificacion = usuario
        obj.fecha_modificacion = datetime.now(timezone.utc)

        self.db.add(obj)
        self.db.commit()
        return True
