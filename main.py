from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routers import router as api_router
from app.core import custom_exception_register
from app.core.config import get_settings
from app.middleware.security_middleware import add_security_middleware

settings = get_settings()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="API para gestión de ventas de productos y servicios turísticos",
    version=settings.PROJECT_VERSION,
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,  # En producción, especificar los orígenes permitidos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registrar manejadores de excepciones personalizados
custom_exception_register(app)

# Registrar middleware de seguridad
add_security_middleware(app)

# Incluir el router de la API
app.include_router(api_router)


@app.get("/")
async def read_root():
    return {
        "message": f"¡Bienvenido a {settings.PROJECT_NAME}!",
        "version": settings.PROJECT_VERSION,
        "docs_url": "/docs",
    }


@app.get("/health")
async def health_check():
    """Endpoint para verificar el estado del servicio."""
    return {"status": "ok", "version": settings.PROJECT_VERSION}
