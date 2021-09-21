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


class CreateKeyParameters(BaseModel):
    cake: str
