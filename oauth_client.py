"""This is an example usage of fastapi-sso.
"""
import os
import traceback
from typing import Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi_sso.sso.base import OpenID
from starlette import status
from starlette.requests import Request
from starlette.responses import RedirectResponse

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
app = FastAPI()

from fastapi_sso.sso.generic import create_provider

discovery = {
    "authorization_endpoint": "http://localhost:5000/oauth/authorize",
    "token_endpoint": "http://localhost:5000/oauth/token",
    "userinfo_endpoint": "http://localhost:5000/api/me",
}


def convert_openid(response: Dict[str, Any]) -> OpenID:
    """Convert user information returned by OIDC"""
    print(response)
    return OpenID(display_name=response["username"])


SSOProvider = create_provider(
    name="oidc",
    default_scope=['profile'],
    discovery_document=discovery,
    response_convertor=convert_openid
)

sso = SSOProvider(
    client_id="F3aZSAzr9xdBLN6lFuDaTVya",
    client_secret="zxom2go7xZWEpgq5TQqDEekEJj0AqXGt48HNVPKkq2mlOj0a",
    redirect_uri="http://localhost:8000/login/callback",
    allow_insecure_http=True
)


@app.get("/")
async def sso_login():
    """Generate login url and redirect"""
    return RedirectResponse('/login', status.HTTP_302_FOUND)


@app.get("/login")
async def sso_login():
    """Generate login url and redirect"""
    return await sso.get_login_redirect()


@app.get("/login/callback")
async def sso_callback(request: Request):
    """Process login response from OIDC and return user info"""
    try:
        user = await sso.verify_and_process(request)
    except:
        traceback.print_exc()
        user = None

    if user is None:
        raise HTTPException(401, "Failed to fetch user information")
    return {
        "id": user.id,
        "picture": user.picture,
        "display_name": user.display_name,
        "email": user.email,
        "provider": user.provider,
    }


if __name__ == "__main__":
    uvicorn.run(app="oauth_client:app", host="127.0.0.1", port=8000)
