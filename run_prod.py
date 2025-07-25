import multiprocessing
import uvicorn
from app.core.config import settings


def run():
    config = uvicorn.Config(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        workers=settings.WORKERS,
        log_config=None,  # Use default logging
        access_log=False if not settings.DEBUG else True,
        timeout_keep_alive=60,
        limit_max_requests=1000,
    )
    server = uvicorn.Server(config)
    server.run()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    run()
