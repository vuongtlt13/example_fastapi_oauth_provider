from typing import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession

from database import AsyncSessionLocal


async def get_session() -> AsyncIterator[AsyncSession]:
    async with AsyncSessionLocal() as session:
        yield session
