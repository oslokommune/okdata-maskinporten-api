from typing import List

from pydantic import BaseModel


class MaskinportenClientIn(BaseModel):
    name: str
    description: str
    scopes: List[str]


class MaskinportenClientOut(BaseModel):
    client_id: str
    name: str
    description: str
    scopes: List[str]


class ClientKey(BaseModel):
    key_id: str
    key: str


class ClientKeyMetadata(BaseModel):
    key_id: str
    client_id: str
