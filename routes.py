import time
import uuid

from fastapi import APIRouter, Depends, Body, Request, Form
from fastapi.responses import RedirectResponse
from fastapi_oauth.base import OAuth2Error
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from werkzeug.security import gen_salt

from dep import get_current_user, get_session, extract_session_in_request
from models import User, OAuthClient
from oauth2 import AUTHORIZATION, require_oauth
from schema import CreateClientRequest
from session import SESSIONS, SESSION_KEY
from template import TEMPLATE

router = APIRouter()


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@router.get('/')
async def home(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    if current_user:
        clients = (await session.execute(select(OAuthClient).filter_by(user_id=current_user.id))).scalars()
    else:
        clients = []

    return TEMPLATE.TemplateResponse(
        name='home.html.jinja2',
        context=dict(
            request=request,
            user=current_user,
            clients=clients
        )
    )


@router.post('/')
async def home_post(
    *,
    next: str = None,
    username: str = Form(),
    session: AsyncSession = Depends(get_session)
):
    user = (await session.scalars(select(User).filter_by(email=username))).first()
    if not user:
        user = User(email=username)
        session.add(user)
        await session.commit()

    new_session = uuid.uuid4().hex
    SESSIONS[new_session] = user.id

    # if user is not just to log in, but need to head back to the auth page, then go for it

    if next:
        response = RedirectResponse(next, status_code=status.HTTP_302_FOUND)
    else:
        response = RedirectResponse('/', status_code=status.HTTP_302_FOUND)
    response.set_cookie(SESSION_KEY, new_session)
    return response


@router.get('/logout')
def logout(
    session_id: str = Depends(extract_session_in_request)
):
    if session_id and session_id in SESSIONS:
        del SESSIONS[session_id]
    return RedirectResponse('/', status_code=status.HTTP_302_FOUND)


@router.get('/create_client')
async def create_client_index(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    if not current_user:
        return RedirectResponse('/', status_code=status.HTTP_302_FOUND)
    return TEMPLATE.TemplateResponse(
        'create_client.html.jinja2',
        context=dict(
            request=request
        )
    )


@router.post('/create_client')
async def create_client(
    *,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    client_info: CreateClientRequest = Depends()
):
    if not current_user:
        return RedirectResponse('/', status_code=status.HTTP_302_FOUND)
    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuthClient(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=current_user.id,
    )

    client_info.grant_types = split_by_crlf(client_info.grant_types)
    client_info.redirect_uris = split_by_crlf(client_info.redirect_uris)
    client_info.response_types = split_by_crlf(client_info.response_types)
    client_metadata = client_info.__dict__
    client.set_client_metadata(client_metadata)

    if client_info.token_endpoint_auth_method == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)

    session.add(client)
    await session.commit()
    return RedirectResponse('/', status_code=status.HTTP_302_FOUND)


@router.get('/oauth/authorize')
async def authorize(
    *,
    current_user: User = Depends(get_current_user),
    request: Request
):
    # if user log status is not true (Auth server), then to log it in
    if not current_user:
        return RedirectResponse(f"/?next={request.url}")
    try:
        grant = await AUTHORIZATION.get_consent_grant(
            end_user=current_user,
            request=request
        )
    except OAuth2Error as error:
        return error.error
    return TEMPLATE.TemplateResponse(
        name='authorize.html.jinja2',
        context=dict(
            request=request,
            user=current_user,
            grant=grant
        )
    )


@router.post('/oauth/authorize')
async def authorize(
    *,
    current_user: User = Depends(get_current_user),
    request: Request,
    confirm: bool = Body()
):
    # if user log status is not true (Auth server), then to log it in
    if not current_user:
        return RedirectResponse(f"/?next={request.url}")
    if confirm:
        grant_user = current_user
    else:
        grant_user = None
    return AUTHORIZATION.create_authorization_response(grant_user=grant_user)


@router.post('/oauth/token')
def issue_token():
    return AUTHORIZATION.create_token_response()


@router.post('/oauth/revoke')
def revoke_token():
    return AUTHORIZATION.create_endpoint_response('revocation')


@router.get('/api/me')
@require_oauth('profile')
def api_me(
    current_user: User = Depends(get_current_user),
):
    return dict(
        id=current_user.id,
        username=current_user.username
    )
