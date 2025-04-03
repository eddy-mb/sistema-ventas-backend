from fastapi import APIRouter

from app.core.config import get_settings

from .v1.auth import router as auth_router
from .v1.clientes import router as cliente_router
from .v1.roles import router as role_router

settings = get_settings()

# Router principal de la API v1
router = APIRouter(prefix=settings.API_V1_PREFIX)


# Incluir routers de los diferentes módulos
router.include_router(auth_router)
router.include_router(role_router)
router.include_router(cliente_router)
