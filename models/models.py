from typing import List

from pydantic import BaseModel


class MaskinportenClient(BaseModel):
    name: str
    description: str
    scopes: List[str]
