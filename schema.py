from typing import Any

from fastapi import Form
from pydantic import BaseModel
from pydantic.dataclasses import dataclass


class LoginRequest(BaseModel):
    username: str


@dataclass
class CreateClientRequest:
    client_name: str = Form()
    client_uri: str = Form()
    grant_types: str = Form()
    redirect_uris: str = Form()
    response_types: str = Form()
    scope: str = Form()
    token_endpoint_auth_method: str = Form()
