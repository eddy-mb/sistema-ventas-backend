import os

from dotenv import load_dotenv
from sqlmodel import Session, SQLModel, create_engine

load_dotenv()
DB_HOST = os.getenv("DB_HOST")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_DATABASE = os.getenv("DB_DATABASE")
DB_PORT = os.getenv("DB_PORT")

SQL_ECHO = os.getenv("SQL_ECHO")

DATABASE_URL = (
    f"postgresql://{DB_USERNAME}:{DB_PASSWORD}@"
    f"{DB_HOST}:{DB_PORT}/{DB_DATABASE}"
)

engine = create_engine(DATABASE_URL, echo=bool(SQL_ECHO))

metadata = SQLModel.metadata


def get_session():
    with Session(engine) as session:
        yield session
