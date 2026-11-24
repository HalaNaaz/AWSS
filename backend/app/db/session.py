from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from backend.app.core.config import settings

# In dev / test, handle sqlite or postgres gracefully
database_url = settings.DATABASE_URL
engine = create_async_engine(
    database_url,
    echo=(settings.ENVIRONMENT == "development" and False),
    future=True,
    pool_pre_ping=True
)

async_session_factory = async_sessionmaker(
    engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    class_=AsyncSession
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
