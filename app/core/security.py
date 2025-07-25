from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import bcrypt
import jwt

from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from pydantic import EmailStr
from sqlalchemy import UUID

from app.core.config import settings


# Password hashing with bcrypt
def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


# JWT token creation
def create_jwt_token(
    subject: str, expires_delta: timedelta, token_type: str = "access"
) -> str:
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {"sub": subject, "exp": expire, "type": token_type}
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def create_access_token(user_access_id: UUID) -> str:
    return create_jwt_token(
        subject=str(user_access_id),
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access",
    )


def create_refresh_token(user_access_id: UUID) -> str:
    return create_jwt_token(
        subject=str(user_access_id),
        expires_delta=timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES),
        token_type="refresh",
    )


def create_reset_token(email: EmailStr) -> str:
    return create_jwt_token(
        subject=email,
        expires_delta=timedelta(minutes=settings.RESET_TOKEN_EXPIRE_MINUTES),
        token_type="reset",
    )


# Token verification
def verify_jwt_token(token: str, expected_type: str) -> Optional[str]:
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        if payload.get("type") != expected_type:
            return None

        access_id: str = payload.get("sub")
        if access_id is None:
            return None

        return access_id
    except JWTError:
        return None


# JWT Bearer for API endpoints that require auth
class JWTBearer(HTTPBearer):
    async def __call__(self, request: Request) -> Tuple[str, str]:
        credentials: HTTPAuthorizationCredentials =\
              await super().__call__(request)
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authorization code.",
            )

        if credentials.scheme != "Bearer":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authentication scheme.",
            )

        email = verify_jwt_token(credentials.credentials, "access")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid token or expired token.",
            )

        return email, credentials.credentials
