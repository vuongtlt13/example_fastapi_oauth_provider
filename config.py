from typing import Any, Dict, Optional

from fastapi_oauth.common.setting import OAuthSetting
from pydantic import AnyUrl, validator


class Settings(OAuthSetting):
    API_PREFIX: str = "/api"

    SECRET_KEY: str

    ACCESS_TOKEN_EXPIRE_MINUTES: int

    MYSQL_HOST: str
    MYSQL_PORT: str
    MYSQL_USER: str
    MYSQL_PASSWORD: str
    MYSQL_DATABASE: str

    SQLALCHEMY_DEBUG: bool = False

    SQLALCHEMY_DATABASE_URI: Optional[AnyUrl] = None

    @validator("SQLALCHEMY_DATABASE_URI", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v
        return f'mysql+aiomysql://{values.get("MYSQL_USER")}:{values.get("MYSQL_PASSWORD")}' \
               f'@{values.get("MYSQL_HOST")}:{values.get("MYSQL_PORT")}/{values.get("MYSQL_DATABASE")}'

    FIRST_SUPERUSER: str
    FIRST_SUPERUSER_PASSWORD: str

    class Config:
        case_sensitive = True
        env_file = ".env"


SETTING: Settings = Settings()
