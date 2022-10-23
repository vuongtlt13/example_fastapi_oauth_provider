import time
from typing import Any

from fastapi_oauth import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
from inflection import pluralize, underscore
from sqlalchemy import BigInteger, String, ForeignKey
from sqlalchemy import Column
from sqlalchemy.orm import relationship, as_declarative, declared_attr


@as_declarative()
class Base:
    id: Any
    __name__: str

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        super().__init__()

    # Generate __tablename__ automatically
    @declared_attr
    def __tablename__(self) -> str:
        return underscore(pluralize(self.__name__))


class User(Base):
    id = Column(BigInteger, primary_key=True)
    email = Column(String(255), unique=True)
    password = Column(String(255), nullable=False)

    def get_user_id(self):
        return self.id


class OAuthClient(Base, OAuth2ClientMixin):
    __tablename__ = 'oauth_clients'

    id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey('user.id', ondelete='CASCADE'))

    user = relationship('User')


class OAuthAuthorizationCode(Base, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'oauth_authorization_codes'

    id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey('user.id', ondelete='CASCADE'))

    user = relationship('User')


class OAuthToken(Base, OAuth2TokenMixin):
    __tablename__ = 'oauth_token'

    id = Column(BigInteger, primary_key=True)
    user_id = Column(
        BigInteger, ForeignKey('user.id', ondelete='CASCADE'))
    user = relationship('User')

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()
