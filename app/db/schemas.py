from pydantic import BaseModel, EmailStr, constr
from typing import Optional


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[EmailStr] = None


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: constr(min_length=8)


class UserInDB(UserBase):
    hashed_password: str
    is_active: bool


class ResetPassword(BaseModel):
    token: str
    new_password: constr(min_length=8)


class NewPassword(BaseModel):
    token: str
    new_password: constr(min_length=8)
