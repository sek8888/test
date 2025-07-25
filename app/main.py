from fastapi import FastAPI # , Request
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.routes import auth, orders, api


app = FastAPI()

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# @app.middleware("http")
# async def security_headers(request: Request, call_next):
#     response = await call_next(request)
#     response.headers["X-Content-Type-Options"] = "nosniff"
#     response.headers["X-Frame-Options"] = "DENY"
#     response.headers["Content-Security-Policy"] = "default-src 'self'"

#     return response

# app.add_middleware(security_headers)

# Include routes
app.include_router(auth.router, prefix="/api/auth")
app.include_router(orders.router, prefix="/api/order")
app.include_router(api.router, prefix="/api")
