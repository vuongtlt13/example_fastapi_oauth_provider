from typing import Optional

from fastapi_oauth import (
    AuthorizationServer,
    ResourceProtector,
    create_query_client_func,
    create_save_token_func,
    create_revocation_endpoint,
    create_bearer_token_validator,
)
from fastapi_oauth.provider.setting import OAuthSetting
from fastapi_oauth.rfc6749 import grants, OAuth2Request
from fastapi_oauth.rfc7636 import CodeChallenge
from fastapi import FastAPI, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import User, OAuthClient, OAuthAuthorizationCode, OAuthToken


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        'client_secret_basic',
        'client_secret_post',
        'none',
    ]

    async def save_authorization_code(self, code, request: OAuth2Request, session: AsyncSession) -> OAuthAuthorizationCode:
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


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    async def authenticate_user(self, username: str, password: str, session: AsyncSession) -> Optional[User]:
        user = (await session.scalars(select(User).filter(email=username))).first()
        if user is not None and user.check_password(password):
            return user


class RefreshTokenGrant(grants.RefreshTokenGrant):
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


query_client = create_query_client_func(OAuthClient)
save_token = create_save_token_func(OAuthToken)
require_oauth = ResourceProtector()
AUTHORIZATION: AuthorizationServer = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)


def config_oauth(config: OAuthSetting):
    AUTHORIZATION.init_app(config)

    # support all grants
    AUTHORIZATION.register_grant(grants.ImplicitGrant)
    AUTHORIZATION.register_grant(grants.ClientCredentialsGrant)
    AUTHORIZATION.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    AUTHORIZATION.register_grant(PasswordGrant)
    AUTHORIZATION.register_grant(RefreshTokenGrant)

    # support revocation
    revocation_cls = create_revocation_endpoint(OAuthToken)
    AUTHORIZATION.register_endpoint(revocation_cls)

    # protect resource
    bearer_cls = create_bearer_token_validator(OAuthToken)
    require_oauth.register_token_validator(bearer_cls())
