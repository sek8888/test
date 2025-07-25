from typing import AsyncGenerator, Any

from sqlalchemy.ext.asyncio import (
    create_async_engine, async_sessionmaker, AsyncSession
)

from sqlalchemy.exc import SQLAlchemyError, DBAPIError
from app.utils.logger import logger
from app.core.errors import DatabaseError
from app.core.config import settings


# Create async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    # future=True,
    # pool_size=20,
    # max_overflow=0,
    # pool_pre_ping=True,
)

# Session factory
AsyncSessionLocal = async_sessionmaker(
    engine, expire_on_commit=False, autoflush=False
)


async def get_db() -> AsyncGenerator[AsyncSession, Any]:
    """
    Complete async session manager with:
    - Detailed error logging
    - Proper exception hierarchy
    """
    async with AsyncSessionLocal() as session:
        try:
            logger.debug("Database session started")
            yield session

        except DBAPIError as e:
            await session.rollback()
            logger.critical(f"Database API error: {str(e)}", exc_info=True)
            raise DatabaseError("Connection failed") from e

        except SQLAlchemyError as e:
            await session.rollback()
            logger.error(f"Database operation failed: {str(e)}", exc_info=True)
            raise DatabaseError("Operation failed") from e

        except Exception as e:
            await session.rollback()
            logger.error(f"Unexpected database error: {str(e)}", exc_info=True)
            raise DatabaseError("Internal error") from e

        finally:
            await session.close()
            logger.debug("Database session closed")
