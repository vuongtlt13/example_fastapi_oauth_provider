from typing import AsyncIterator, Optional

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from database import AsyncSessionLocal
from models import User
from session import SESSION_KEY, get_user_from_session


async def get_session() -> AsyncIterator[AsyncSession]:
    async with AsyncSessionLocal() as session:
        yield session


async def extract_session_in_request(
    request: Request,
) -> Optional[str]:
    return request.cookies.get(SESSION_KEY, None)


async def get_current_user(
    session_id: str = Depends(extract_session_in_request),
    session: AsyncSession = Depends(get_session),

) -> Optional[User]:
    return await get_user_from_session(session_id, session)
