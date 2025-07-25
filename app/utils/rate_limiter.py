# from datetime import datetime, timedelta
# from fastapi import HTTPException, Request
# from fastapi.responses import JSONResponse
# from typing import Tuple
# import redis.asyncio as redis
# from app.core.config import settings


class RateLimiter:
    def __init__(self, times: int, seconds: int):
        """
        Initialize rate limiter
        :param times: Number of allowed requests
        :param seconds: Time window in seconds
        """
        self.times = times
        self.seconds = seconds
        self.redis_client = None

    # async def init_redis(self):
    #     """Initialize Redis connection"""
    #     self.redis_client = redis.from_url(settings.REDIS_URL)

    # async def _get_cache_key(self, request: Request) -> str:
    #     """Generate cache key based on client IP and route"""
    #     client_ip = request.client.host if request.client else "unknown"
    #     route = request.url.path
    #     return f"rate_limit:{client_ip}:{route}"

    # async def _get_current_count(self, key: str) -> Tuple[int, float]:
    #     """Get current request count and expiration time"""
    #     if not self.redis_client:
    #         await self.init_redis()

    #     current = await self.redis_client.get(key)
    #     if current:
    #         count, expiry = current.decode().split("|")
    #         return int(count), float(expiry)
    #     return 0, 0

    # async def _update_count(self, key: str, count: int, expiry: float):
    #     """Update request count in Redis"""
    #     await self.redis_client.setex(
    #         key, int(self.seconds), f"{count}|{expiry}")

    # async def limit(self, request: Request):
    #     """Rate limiting decorator implementation"""
    #     if not settings.RATE_LIMITING_ENABLED:
    #         return

    #     key = await self._get_cache_key(request)
    #     current_count, expiry = await self._get_current_count(key)
    #     now = datetime.now().timestamp()

    #     if expiry < now:
    #         # Reset counter if time window has passed
    #         current_count = 0
    #         new_expiry = (
    #             datetime.now() + timedelta(seconds=self.seconds)).timestamp()
    #     else:
    #         new_expiry = expiry

    #     current_count += 1

    #     if current_count > self.times:
    #         retry_after = int(expiry - now) if expiry > now else self.seconds
    #         raise HTTPException(
    #             status_code=429,
    #             detail="Too many requests",
    #             headers={"Retry-After": str(retry_after)},
    #         )

    #     await self._update_count(key, current_count, new_expiry)

    # async def __call__(self, request: Request):
    #     """Make the instance callable for FastAPI dependency"""
    #     return await self.limit(request)

    # @staticmethod
    # async def rate_limit_exceeded_handler(
    #     request: Request, exc: HTTPException
    # ):
    #     """Custom handler for rate limit exceeded"""
    #     return JSONResponse(
    #         content={"detail": exc.detail},
    #         status_code=429,
    #         headers={"Retry-After": exc.headers.get("Retry-After", "60")},
    #     )
