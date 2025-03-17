from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.routers import router as api_router
from app.core import custom_exception_register

app = FastAPI(
    title="Sistema de Ventas Ama Wara",
    description="API para gestión de ventas de productos y servicios turísticos",
    version="1.0.0",
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción, especificar los orígenes permitidos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registrar manejadores de excepciones personalizados
custom_exception_register(app)


# Incluir el router de la API
app.include_router(api_router)


@app.get("/")
async def read_root():
    return {"message": "¡Hola, FastAPI!"}
