from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class MaskinportenEnvironment(str, Enum):
    test = "test"
    prod = "prod"


class MaskinportenClientIn(BaseModel):
    name: str
    description: str
    scopes: list[str]
    env: MaskinportenEnvironment


class MaskinportenClientOut(BaseModel):
    client_id: str
    client_name: str
    description: str
    scopes: list[str]
    created: datetime
    last_updated: datetime
    active: bool


class CreateClientKeyIn(BaseModel):
    destination_aws_account: Optional[str]
    destination_aws_region: Optional[str]


class CreateClientKeyOut(BaseModel):
    kid: str
    ssm_params: Optional[list[str]]
    keystore: Optional[str]
    key_password: Optional[str]


class DeleteClientKeyOut(BaseModel):
    deleted_from_ssm: bool


class ClientKeyMetadata(BaseModel):
    kid: str
    client_id: str
    created: datetime
    expires: datetime
    last_updated: datetime
