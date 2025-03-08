# app/services/base_service.py

from datetime import datetime, timezone
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar

from sqlmodel import col, select

from app.dependencies.db import SessionDep
from app.models.auditoria.base_model import BaseModel

T = TypeVar("T", bound=BaseModel)


class BaseService(Generic[T]):
    """Servicio base para operaciones CRUD con auditoría"""

    def __init__(
        self,
        model: Type[T],
        db: SessionDep,
        usuario_actual: str | None = None,
    ):
        self.model = model
        self.db = db
        self.usuario_actual = usuario_actual or "sistema"

    def create(self, obj_data: Dict[str, Any]) -> T:
        """Crea un nuevo registro con auditoría"""
        db_obj = self.model(**obj_data)
        db_obj._usuario_creacion = self.usuario_actual
        db_obj._fecha_creacion = datetime.now(timezone.utc)
        self.db.add(db_obj)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def update(self, id: int, obj_data: Dict[str, Any]) -> Optional[T]:
        """Actualiza un registro con auditoría"""
        db_obj = self.get_by_id(id)
        if not db_obj:
            return None

        for key, value in obj_data.items():
            setattr(db_obj, key, value)

        db_obj._usuario_modificacion = self.usuario_actual
        db_obj._fecha_modificacion = datetime.now(timezone.utc)

        self.db.add(db_obj)
        self.db.commit()
        self.db.refresh(db_obj)
        return db_obj

    def get_by_id(self, id: int) -> Optional[T]:
        """Obtiene un registro por su ID"""
        query = select(self.model).where(
            self.model.id == id, col(self.model._estado).is_(True)
        )
        return self.db.exec(query).first()

    def get_all(self) -> List[T]:
        """Obtiene todos los registros activos"""
        query = select(self.model).where(col(self.model._estado).is_(True))
        return list(self.db.exec(query).all())

    def delete(self, id: int) -> bool:
        """Eliminación lógica (cambio de estado)"""
        db_obj = self.get_by_id(id)
        if not db_obj:
            return False

        db_obj._estado = False
        db_obj._usuario_modificacion = self.usuario_actual
        db_obj._fecha_modificacion = datetime.now(timezone.utc)

        self.db.add(db_obj)
        self.db.commit()
        return True
