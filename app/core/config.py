from pydantic import EmailStr
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # System
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost/db"

    # Security
    SECRET_KEY: str = "your-secret-key-here"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    RESET_TOKEN_EXPIRE_MINUTES: int = 60  # 1 hour
    ALGORITHM: str = "HS256"
    CSRF_KEY: str = "a_very_strong_password_123!"

    # Cookies
    COOKIE_DOMAIN: Optional[str] = None
    SECURE_COOKIES: bool = True
    SAME_SITE_COOKIES: str = "lax"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    # Email
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: Optional[int] = None
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    EMAILS_FROM_EMAIL: Optional[EmailStr] = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
