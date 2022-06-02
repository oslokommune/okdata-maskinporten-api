from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class MaskinportenEnvironment(str, Enum):
    test = "test"
    prod = "prod"


class MaskinportenClientIn(BaseModel):
    team_id: UUID
    provider: str
    integration: str
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


# TODO: Check if any keycloak resources needs to be deleted
class DeleteMaskinportenClientOut(BaseModel):
    client_id: str


class CreateClientKeyIn(BaseModel):
    destination_aws_account: Optional[str]
    destination_aws_region: Optional[str]


class CreateClientKeyOut(BaseModel):
    kid: str
    ssm_params: Optional[list[str]]
    keystore: Optional[str]
    key_alias: Optional[str]
    key_password: Optional[str]


class ClientKeyMetadata(BaseModel):
    kid: str
    client_id: str
    created: datetime
    expires: datetime
    last_updated: datetime
