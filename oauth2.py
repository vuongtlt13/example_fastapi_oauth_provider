import functools
import logging
from contextlib import contextmanager
from typing import Optional, List

from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi_oauth.common.errors import OAuth2Error
from fastapi_oauth.common.setting import OAuthSetting
from fastapi_oauth.rfc6749 import OAuth2Request, ResourceProtector as _ResourceProtector, AuthorizationServer, \
    MissingAuthorizationError
from fastapi_oauth.rfc6749.grants import AuthorizationCodeGrant as _AuthorizationCodeGrant, \
    ResourceOwnerPasswordCredentialsGrant, RefreshTokenGrant as _RefreshTokenGrant, \
    ImplicitGrant, ClientCredentialsGrant
from fastapi_oauth.rfc6749.signals import token_authenticated
from fastapi_oauth.rfc7636.challenge import CodeChallenge
from fastapi_oauth.utils.functions import create_revocation_endpoint, create_bearer_token_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.requests import Request
from starlette.responses import JSONResponse

from config import SETTING
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


class ResourceProtector(_ResourceProtector):

    async def acquire_token(self, request: Request, session: AsyncSession, scopes: List[str] = None):
        """A method to acquire current valid token with the given scope.

        :param session: Async SQLAlchemy session
        :param request: Starlette Request instance
        :param scopes: a list of scope values
        :return: token object
        """
        token = await self.validate_request(scopes, request, session)
        token_authenticated.send(self, token=token)
        return token

    @contextmanager
    def acquire(self, request: Request, session: AsyncSession, scopes: List[str] = None):
        """The with statement of ``require_oauth``. Instead of using a
        decorator, you can use a with statement instead::

            @app.route('/api/user')
            def user_api():
                with require_oauth.acquire('profile') as token:
                    user = User.query.get(token.user_id)
                    return jsonify(user.to_dict())
        """
        try:
            yield self.acquire_token(scopes=scopes, request=request, session=session)
        except OAuth2Error:
            raise

    def require_scope(self, scopes=None, optional=False):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                # find request object
                request = None
                session = None
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                    elif isinstance(arg, AsyncSession):
                        session = arg

                for _, v in kwargs.items():
                    if isinstance(v, Request):
                        request = v
                    elif isinstance(v, AsyncSession):
                        session = v

                if request is None:
                    _logger.error("You must add `request` argument in your function!")
                    raise OAuth2Error(
                        description="You must add `request` argument in your function!",
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )

                if session is None:
                    _logger.error("You must add `session` argument in your function!")
                    raise OAuth2Error(
                        description="You must add `session` argument in your function!",
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )

                try:
                    self.acquire_token(scopes=scopes, request=request, session=session)
                except MissingAuthorizationError:
                    if optional:
                        return f(*args, **kwargs)
                    raise
                except OAuth2Error:
                    raise
                return f(*args, **kwargs)

            return decorated

        return wrapper


resource_protector = ResourceProtector()
require_scope = resource_protector.require_scope
AUTHORIZATION: AuthorizationServer = AuthorizationServer(
    config=SETTING,
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
    AUTHORIZATION.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    AUTHORIZATION.register_grant(PasswordGrant)
    AUTHORIZATION.register_grant(RefreshTokenGrant)

    # support revocation
    revocation_cls = create_revocation_endpoint(OAuthToken)
    AUTHORIZATION.register_endpoint(revocation_cls)

    # protect resource
    bearer_cls = create_bearer_token_validator(OAuthToken)
    resource_protector.register_token_validator(bearer_cls())
