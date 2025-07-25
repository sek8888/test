from typing import Annotated
from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse
from app.core.csrf_token import generate_csrf_token, csrf_protected

router = APIRouter()


@router.get("/get-csrf")
async def get_csrf(payload_id: str):
    csrf_token = await generate_csrf_token(payload_id)
    return {"csrf_token": csrf_token}
