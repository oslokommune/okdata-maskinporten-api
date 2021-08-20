import logging
import os

from typing import List

from fastapi import APIRouter, status

from models import (
    CreateMaskinportenClientBody,
    MaskinportenClient,
    ClientKey,
    ClientKeyMetadata,
)

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))


router = APIRouter()


@router.post("", status_code=status.HTTP_201_CREATED, response_model=MaskinportenClient)
def create_client(body: CreateMaskinportenClientBody):
    # TODO: Implement real functionality
    return MaskinportenClient(
        client_id="some-client-id",
        name=body.name,
        description=body.description,
        scopes=body.scopes,
    )


@router.post(
    "/{client_id}/keys", status_code=status.HTTP_201_CREATED, response_model=ClientKey
)
def create_client_key(client_id: str):
    # TODO: Implement real functionality
    client_key = ClientKey(key_id=f"{client_id}-uuid", key="some-key")
    return client_key


@router.get(
    "/{client_id}/keys",
    status_code=status.HTTP_200_OK,
    response_model=List[ClientKeyMetadata],
)
def list_client_keys(client_id: str):
    # TODO: Implement real functionality
    return [ClientKeyMetadata(key_id=f"{client_id}-uuid", client_id=client_id)]
