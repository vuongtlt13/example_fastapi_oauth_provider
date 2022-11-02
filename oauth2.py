import logging
from typing import Optional

from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi_oauth.common.errors import OAuth2Error
from fastapi_oauth.common.setting import OAuthSetting
from fastapi_oauth.common.types import ContextDependency
from fastapi_oauth.rfc6749 import OAuth2Request, AuthorizationServer, \
    ResourceProtector
from fastapi_oauth.rfc6749.grants import AuthorizationCodeGrant as _AuthorizationCodeGrant, \
    ResourceOwnerPasswordCredentialsGrant, RefreshTokenGrant as _RefreshTokenGrant, \
    ImplicitGrant, ClientCredentialsGrant
from fastapi_oauth.rfc7636.challenge import CodeChallenge
from fastapi_oauth.utils.functions import create_revocation_endpoint, create_bearer_token_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.responses import JSONResponse

from dep import get_session, get_current_user
from models import User, OAuthClient, OAuthAuthorizationCode, OAuthToken

_logger = logging.getLogger(__name__)


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        'client_secret_basic',
        'client_secret_post',
        'none',
    ]

    async def save_authorization_code(self, code, request: OAuth2Request,
                                      session: AsyncSession) -> OAuthAuthorizationCode:
        request_json = request.json
        code_challenge = request_json.get('code_challenge')
        code_challenge_method = request_json.get('code_challenge_method')
        auth_code = OAuthAuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        session.add(auth_code)
        await session.commit()
        return auth_code

    async def query_authorization_code(self, code: str, client: OAuthClient, session: AsyncSession) -> Optional[
        OAuthAuthorizationCode]:
        auth_code = (await session.scalars(select(OAuthAuthorizationCode).filter_by(
            code=code,
            client_id=client.client_id
        ))).first()
        if auth_code and not auth_code.is_expired():
            return auth_code

    async def delete_authorization_code(self, authorization_code, session: AsyncSession):
        await session.delete(authorization_code)
        await session.commit()

    async def authenticate_user(self, authorization_code: OAuthAuthorizationCode, session: AsyncSession) -> Optional[
        User]:
        return (await session.scalars(select(User).filter(User.id == authorization_code.user_id))).first()


class PasswordGrant(ResourceOwnerPasswordCredentialsGrant):
    async def authenticate_user(self, username: str, password: str, session: AsyncSession) -> Optional[User]:
        user = (await session.scalars(select(User).filter(email=username))).first()
        if user is not None and user.check_password(password):
            return user


class RefreshTokenGrant(_RefreshTokenGrant):
    async def authenticate_refresh_token(self, refresh_token, session: AsyncSession) -> Optional[OAuthToken]:
        token = (await session.scalars(select(OAuthToken).filter(refresh_token=refresh_token))).first()
        if token and token.is_refresh_token_active():
            return token

    async def authenticate_user(self, credential, session: AsyncSession) -> Optional[User]:
        return (await session.scalars(select(User).filter(User.id == credential.user_id))).first()

    async def revoke_old_credential(self, credential, session: AsyncSession):
        credential.revoked = True
        session.add(credential)
        await session.commit()


resource_protector = ResourceProtector()
require_scope = resource_protector.require_scope
AUTHORIZATION: AuthorizationServer = AuthorizationServer(
    context_dependency=ContextDependency(
        get_db_session=get_session,
        get_user_from_session=get_current_user,
        get_user_from_token=get_current_user,
    ),
    oauth_client_model_cls=OAuthClient,
    oauth_token_model_cls=OAuthToken,
)


def config_oauth(app: FastAPI, config: OAuthSetting):
    @app.exception_handler(OAuth2Error)
    async def oauth2_exception_handler(_: Request, exc: OAuth2Error):
        return JSONResponse(
            status_code=exc.status_code,
            content=jsonable_encoder({
                "message": exc.description,
                "success": False,
                "data": None,
                "error": {
                    "code": exc.error
                }
            }),
        )

    AUTHORIZATION.init_app(config)

    # support all grants
    AUTHORIZATION.register_grant(ImplicitGrant)
    AUTHORIZATION.register_grant(ClientCredentialsGrant)
    AUTHORIZATION.register_grant(AuthorizationCodeGrant, [CodeChallenge()])
    AUTHORIZATION.register_grant(PasswordGrant)
    AUTHORIZATION.register_grant(RefreshTokenGrant)

    # support revocation
    revocation_cls = create_revocation_endpoint(OAuthToken)
    AUTHORIZATION.register_endpoint(revocation_cls)

    # protect resource
    bearer_cls = create_bearer_token_validator(OAuthToken, User)
    resource_protector.register_token_validator(bearer_cls())
