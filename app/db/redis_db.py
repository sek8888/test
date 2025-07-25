import redis.asyncio

redis = redis.asyncio.from_url("redis://localhost", decode_responses=True)
