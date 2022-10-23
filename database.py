from asyncio import current_task

from sqlalchemy.ext.asyncio import AsyncSession, async_scoped_session, create_async_engine
from sqlalchemy.orm import sessionmaker

from config import SETTING

engine = create_async_engine(
    SETTING.SQLALCHEMY_DATABASE_URI,
    echo=SETTING.SQLALCHEMY_DEBUG,
)

# expire_on_commit=False will prevent attributes from being expired
# after commit.
AsyncSessionLocal = async_scoped_session(
    sessionmaker(
        engine,
        class_=AsyncSession,
    ),
    scopefunc=current_task,
)
# default kwarg autoflush=True
