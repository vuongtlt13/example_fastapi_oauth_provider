from typing import Dict, Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from models import User

SESSION_KEY = "session"

SESSIONS: Dict[str, Any] = {}


async def get_user_from_session(session_id: str, session: AsyncSession) -> Optional[User]:
    user_id = SESSIONS.get(session_id, None)
    if user_id:
        return await session.get(User, user_id)
    return None
