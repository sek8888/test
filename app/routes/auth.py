from datetime import timedelta, datetime, timezone
from typing import Annotated
from fastapi import (
    APIRouter, Depends, HTTPException, Header, Request, Response, status
)
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import EmailStr

from app.core import security
from app.core.config import settings
from app.core.csrf_token import csrf_protected
from app.db import models, schemas
from app.db.session import get_db
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.security import OAuth2PasswordBearer

from jose import JWTError
# from app.utils.email import send_reset_password_email
# from app.utils.rate_limiter import RateLimiter


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
router = APIRouter()
# limiter = RateLimiter(5, 60)  # 5 requests per minute


async def get_current_user(
    request: Request, db=Depends(get_db)
    # token: str = Depends(oauth2_scheme), db=Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token = request.cookies.get("access_token")
    if not token:
        raise credentials_exception

    try:
        access_id = security.verify_jwt_token(token, 'access')
        if access_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user_result = await db.execute(
        select(models.User).where(models.User.access_id == access_id)
    )
    user = user_result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    return user



@router.post("/login")
# @limiter.limit
async def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db=Depends(get_db),
):
    # Validate user exists and password is correct
    user_result = await db.execute(
        select(models.User).where(models.User.email == form_data.username)
    )
    user = user_result.scalar_one_or_none()
    paswd_ok = security.verify_password(form_data.password, user.password)
    if not user or not paswd_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    print(user.id)
    if not user.verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user"
        )

    # Create tokens
    access_token = security.create_access_token(user.access_id)
    refresh_token = security.create_refresh_token(user.access_id)

    # Set HTTP-only cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=settings.SECURE_COOKIES,
        samesite=settings.SAME_SITE_COOKIES,
        domain=settings.COOKIE_DOMAIN,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.SECURE_COOKIES,
        samesite=settings.SAME_SITE_COOKIES,
        domain=settings.COOKIE_DOMAIN,
        max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60,
    )

    return {"status": "OK"}


@router.post("/refresh", response_model=schemas.Token)
async def refresh_token(
    request: Request, response: Response, db=Depends(get_db)
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing"
        )

    email = security.verify_jwt_token(refresh_token, "access")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    # Verify user exists and is active
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Create new tokens
    new_access_token = security.create_access_token(user.email)
    new_refresh_token = security.create_refresh_token(user.email)
    csrf_token = security.generate_csrf_token()

    # Set cookies
    response.set_cookie(
        key="access_token",
        value=f"Bearer {new_access_token}",
        httponly=True,
        secure=settings.SECURE_COOKIES,
        samesite=settings.SAME_SITE_COOKIES,
        domain=settings.COOKIE_DOMAIN,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=settings.SECURE_COOKIES,
        samesite=settings.SAME_SITE_COOKIES,
        domain=settings.COOKIE_DOMAIN,
        max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60,
    )

    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        secure=settings.SECURE_COOKIES,
        samesite=settings.SAME_SITE_COOKIES,
        domain=settings.COOKIE_DOMAIN,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "csrf_token": csrf_token,
    }


@router.post("/forgot-password")
# @limiter.limit
async def forgot_password(
    request: Request,
    email: EmailStr,
    _=csrf_protected(),
    x_csrf_token: Annotated[str | None, Header()] = None,
    x_payload_id: Annotated[str | None, Header()] = None,
    db=Depends(get_db)
):
    # get user by email
    user_result = await db.execute(
        select(models.User).where(
            models.User.email == email,
            models.User.verified == True, # noqa
        )
    )
    if not (user := user_result.scalar_one_or_none()):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # TODO: check is secure using JWT for token reset
    # TODO: check is user has active reset token
    # TODO: clean expired reset tokens
    reset_token = security.create_reset_token(email)
    expires_at = datetime.now(timezone.utc)\
        + timedelta(minutes=settings.RESET_TOKEN_EXPIRE_MINUTES)

    #  Store reset token in database
    db_reset_token = models.PasswordResetToken(
        user_id=user.id,
        token=reset_token,
        expires_at=expires_at,
    )
    db.add(db_reset_token)
    await db.commit()

    # TODO: send email
    # Send email
    # await send_reset_password_email(email, reset_token)

    return {"reset_token": reset_token}


@router.post("/reset-password")
async def reset_password(
    request: Request,
    resp_data: schemas.ResetPassword,
    _=csrf_protected(),
    x_csrf_token: Annotated[str | None, Header()] = None,
    x_payload_id: Annotated[str | None, Header()] = None,
    db=Depends(get_db)
):
    token_result = await db.execute(
        select(models.PasswordResetToken).where(
            models.PasswordResetToken.token == resp_data.token,
            models.PasswordResetToken.expires_at > datetime.now(timezone.utc),
        )
    )

    if not (reset_token := token_result.scalar_one_or_none()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    # Update user password
    user_result = await db.execute(
        select(models.User).where(
            models.User.id == reset_token.user_id,
            models.User.verified == True, # noqa
        )
    )

    if not (user := user_result.scalar_one_or_none()):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user.password = security.get_password_hash(resp_data.new_password)
    await db.delete(reset_token)
    await db.commit()

    return {"message": "Password updated successfully"}


@router.post("/new-password")
async def new_password(
    request: Request,
    resp_data: schemas.NewPassword,
    _=csrf_protected(),
    x_csrf_token: Annotated[str | None, Header()] = None,
    x_payload_id: Annotated[str | None, Header()] = None,
    db: AsyncSession = Depends(get_db)
):
    token_result = await db.execute(
        select(models.PasswordResetToken).where(
            models.PasswordResetToken.token == resp_data.token,
            models.PasswordResetToken.expires_at > datetime.now(timezone.utc),
        )
    )

    if not (reset_token := token_result.scalar_one_or_none()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    # Update user password
    user_result = await db.execute(
        select(models.User).where(
            models.User.id == reset_token.user_id,
            models.User.verified == False,  # noqa
        )
    )

    if not (user := user_result.scalar_one_or_none()):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user.password = security.get_password_hash(resp_data.new_password)
    user.verified = True
    await db.delete(reset_token)
    await db.commit()

    return {"message": "Password updated successfully"}


@router.get("/me")
async def me(current_user: models.User = Depends(get_current_user)):
    return {
        "email": current_user.email,
        "id": current_user.id,
    }


@router.get("/me1", dependencies=[Depends(get_current_user)])
async def me1():
    return {}
