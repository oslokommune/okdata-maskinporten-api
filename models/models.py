from datetime import datetime
from enum import Enum
from typing import Optional, Union
from uuid import UUID

from pydantic import BaseModel, Field


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


class DeleteMaskinportenClientIn(BaseModel):
    aws_account: Optional[str]
    aws_region: Optional[str]


class DeleteMaskinportenClientOut(BaseModel):
    client_id: str
    deleted_ssm_params: list[str]


class CreateClientKeyIn(BaseModel):
    destination_aws_account: Optional[str]
    destination_aws_region: Optional[str]
    enable_auto_rotate: Optional[bool]


class CreateClientKeyOut(BaseModel):
    kid: str
    expires: datetime
    ssm_params: Optional[list[str]]
    keystore: Optional[str]
    key_alias: Optional[str]
    key_password: Optional[str]


class ClientKeyMetadata(BaseModel):
    kid: str
    client_id: str
    expires: datetime


class AuditLogEntry(BaseModel):
    item_id: str = Field(alias="id")
    action: str
    timestamp: datetime
    user: str
    scopes: Union[list[str], None]
    key_id: Union[str, None]

    class Config:
        allow_population_by_field_name = True
