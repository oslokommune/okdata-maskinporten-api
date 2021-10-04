from pydantic import BaseModel


class MaskinportenClientIn(BaseModel):
    name: str
    description: str
    scopes: list[str]
    env: str


class MaskinportenClientOut(BaseModel):
    client_id: str
    client_name: str
    description: str
    scopes: list[str]
    created: str
    last_updated: str
    active: bool


class ClientKeyIn(BaseModel):
    destination_aws_account: str
    destination_aws_region: str


class ClientKeyOut(BaseModel):
    kid: str


class ClientKeyMetadata(BaseModel):
    kid: str
    client_id: str
