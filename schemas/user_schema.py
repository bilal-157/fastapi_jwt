# schemas/user_schema.py (Pydantic Model)
from pydantic import BaseModel

class UserBase(BaseModel):
    email: str
    password: str

class UserCreate(UserBase):
    pass

class User(UserBase):
    id: int

    class Config:
        orm_mode = True  # This allows the model to work with SQLAlchemy models
