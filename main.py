from fastapi import FastAPI

from app.core import custom_exception_register

app = FastAPI()

# Registrar manejadores de excepciones
custom_exception_register(app)


@app.get("/")
async def read_root():
    return {"message": "¡Hola, FastAPI!"}
