import logging
import os

from fastapi import APIRouter, Depends, status

from models import (
    MaskinportenClientIn,
    MaskinportenClientOut,
    ClientKey,
    ClientKeyMetadata,
)
from maskinporten_api.maskinporten_client import MaskinportenClient
from resources.authorizer import AuthInfo, authorize
from resources.errors import error_message_models

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))


router = APIRouter()


@router.post(
    "",
    dependencies=[Depends(authorize(scope="okdata:maskinporten-client:create"))],
    status_code=status.HTTP_201_CREATED,
    response_model=MaskinportenClientOut,
    responses=error_message_models(
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    ),
)
def create_client(
    body: MaskinportenClientIn,
    auth_info: AuthInfo = Depends(),
):
    logger.debug(
        f"Creating new client '{body.name}' in {body.env} with scopes {body.scopes}"
    )

    client = MaskinportenClient(body.env)
    data = {
        "client_name": body.name,
        "description": body.description,
        "scopes": body.scopes,
        "token_endpoint_auth_method": "private_key_jwt",
        "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
        "integration_type": "maskinporten",
        "application_type": "web",
    }
    response = client.request("POST", ["idporten:dcr.write"], json=data).json()

    return MaskinportenClientOut(
        client_id=response["client_id"],
        name=response["client_name"],
        description=response["description"],
        scopes=response["scopes"],
        active=response["active"],
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
    response_model=list[ClientKeyMetadata],
)
def list_client_keys(client_id: str):
    # TODO: Implement real functionality
    return [ClientKeyMetadata(key_id=f"{client_id}-uuid", client_id=client_id)]
