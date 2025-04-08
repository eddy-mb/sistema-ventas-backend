from sqlmodel import SQLModel


class LoginData(SQLModel):
    email: str
    password: str
