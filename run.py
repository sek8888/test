import sys
import subprocess

import uvicorn

from app.core.config import settings


def run_migrations():
    alembic_cmd = [
        sys.executable,  # Uses the same Python interpreter
        "-m",
        "alembic",
        "upgrade",
        "head",
    ]

    try:
        result = subprocess.run(alembic_cmd, check=True, text=True)
        if result.stdout:
            print("Migration output:", result.stdout)

        return True
    except subprocess.CalledProcessError as e:
        print("Migration failed!")
        print("Error:", e.stderr)
        if e.stdout:
            print("Output:", e.stdout)
        return False


def run_server():
    """Run FastAPI application with Uvicorn programmatically"""
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        # workers=settings.WORKERS,
        # ssl_keyfile=settings.SSL_KEYFILE,
        # ssl_certfile=settings.SSL_CERTFILE,
        # log_level=settings.LOG_LEVEL.lower(),
    )


if __name__ == "__main__":
    # upgrade code
    # upgrade DB
    run_migrations()
    # run server
    run_server()
