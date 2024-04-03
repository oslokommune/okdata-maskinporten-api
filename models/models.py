from datetime import datetime
from enum import Enum
from typing import Annotated, Optional, Union
from uuid import UUID

from pydantic import AnyHttpUrl, ConfigDict, BaseModel, Field
from pydantic.functional_serializers import PlainSerializer


# Type definition for customized serialization of datetimes. Uses
# the functional serializer `PlainSerializer` from Pydantic in order
# to override how the field is serialized to JSON. See:
# https://docs.pydantic.dev/latest/concepts/types/#custom-types
# https://docs.pydantic.dev/latest/api/functional_serializers
OffsetDatetime = Annotated[
    datetime,
    PlainSerializer(
        lambda dt: dt.isoformat(timespec="seconds"),
        return_type=str,
        when_used="json",
    ),
]


class MaskinportenEnvironment(str, Enum):
    test = "test"
    prod = "prod"


class ClientType(str, Enum):
    maskinporten = "maskinporten"
    idporten = "idporten"


class ClientIn(BaseModel):
    client_type: ClientType = ClientType.maskinporten

    team_id: UUID
    provider: str
    integration: str
    env: MaskinportenEnvironment

    scopes: Optional[list[str]] = None

    client_uri: Optional[AnyHttpUrl] = None
    frontchannel_logout_uri: Optional[AnyHttpUrl] = None
    redirect_uris: Optional[list[AnyHttpUrl]] = None
    post_logout_redirect_uris: Optional[list[AnyHttpUrl]] = None


class MaskinportenClientIn(ClientIn):
    scopes: list[str]


class IdPortenClientIn(ClientIn):
    client_uri: AnyHttpUrl
    frontchannel_logout_uri: Optional[AnyHttpUrl] = None
    redirect_uris: list[AnyHttpUrl]
    post_logout_redirect_uris: list[AnyHttpUrl]


class MaskinportenClientOut(BaseModel):
    client_id: str
    client_name: str
    description: str
    scopes: list[str]
    created: OffsetDatetime
    last_updated: OffsetDatetime
    active: bool


class DeleteMaskinportenClientIn(BaseModel):
    aws_account: Optional[str]
    aws_region: Optional[str]


class DeleteMaskinportenClientOut(BaseModel):
    client_id: str
    deleted_ssm_params: list[str]


class CreateClientKeyIn(BaseModel):
    destination_aws_account: Optional[str] = None
    destination_aws_region: Optional[str] = None
    enable_auto_rotate: Optional[bool] = False


class CreateClientKeyOut(BaseModel):
    kid: str
    expires: OffsetDatetime
    ssm_params: Optional[list[str]]
    keystore: Optional[str]
    key_alias: Optional[str]
    key_password: Optional[str]


class ClientKeyMetadata(BaseModel):
    kid: str
    client_id: str
    expires: OffsetDatetime


class AuditLogEntry(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    item_id: str = Field(alias="id")
    action: str
    timestamp: OffsetDatetime
    user: str
    scopes: Union[list[str], None]
    key_id: Union[str, None]
