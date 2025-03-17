from fastapi import APIRouter

from .clientes import router as cliente_router

# Router principal de la API v1
router = APIRouter(prefix="/api/v1")


# Incluir routers de los diferentes módulos
router.include_router(cliente_router)
