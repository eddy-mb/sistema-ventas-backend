from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError

from app.core.exceptions import custom_exception_validate


def custom_exception_register(app: FastAPI):
    """Registra todos los manejadores de excepciones en la aplicación."""
    app.add_exception_handler(
        RequestValidationError, custom_exception_validate
    )

    # Aquí puedes agregar más manejadores de excepciones en el futuro
    # app.add_exception_handler(OtraExcepcion, otro_manejador)
