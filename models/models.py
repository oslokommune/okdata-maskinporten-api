from pydantic import BaseModel


class MaskinportenClientIn(BaseModel):
    name: str
    description: str
    scopes: list[str]
    env: str


class MaskinportenClientOut(BaseModel):
    client_id: str
    name: str
    description: str
    scopes: list[str]
    active: bool


class ClientKey(BaseModel):
    kid: str


class ClientKeyMetadata(BaseModel):
    kid: str
    client_id: str


class SomeFittingName(BaseModel):
    destination_aws_account: str
    destination_aws_region: str
