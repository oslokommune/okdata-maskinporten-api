import logging
import os

from fastapi import APIRouter, status

from models import CreateMaskinportenClientBody, MaskinportenClient, ClientKey

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))


router = APIRouter()


@router.post("", status_code=status.HTTP_201_CREATED)
def create_client(body: CreateMaskinportenClientBody):
    # TODO: Implement real functionality
    return MaskinportenClient(
        client_id="some-client-id",
        name=body.name,
        description=body.description,
        scopes=body.scopes,
    )


@router.post("/{client_id}/keys", status_code=status.HTTP_201_CREATED)
def create_client_key(client_id: str):
    # TODO: Implement real functionality
    client_key = ClientKey(key_id=f"{client_id}-uuid", key="some-key")
    return client_key
