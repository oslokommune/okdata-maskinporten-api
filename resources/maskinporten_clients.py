import logging
import os

import requests
from fastapi import APIRouter, Depends, HTTPException, status

from models import (
    MaskinportenClientIn,
    MaskinportenClientOut,
    ClientKey,
    ClientKeyMetadata,
)
from maskinporten_api.keys import generate_key, jwk_from_key
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

    maskinporten_client = MaskinportenClient(body.env)
    data = {
        "client_name": body.name,
        "description": body.description,
        "scopes": body.scopes,
        "token_endpoint_auth_method": "private_key_jwt",
        "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
        "integration_type": "maskinporten",
        "application_type": "web",
    }
    new_client = maskinporten_client.request("POST", ["idporten:dcr.write"], json=data)

    return MaskinportenClientOut(
        client_id=new_client["client_id"],
        name=new_client["client_name"],
        description=new_client["description"],
        scopes=new_client["scopes"],
        active=new_client["active"],
    )


@router.post(
    "/{env}/{client_id}/keys",
    dependencies=[Depends(authorize(scope="okdata:maskinporten-client:create"))],
    status_code=status.HTTP_201_CREATED,
    response_model=ClientKey,
    responses=error_message_models(
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
    ),
)
def create_client_key(
    env: str,
    client_id: str,
    auth_info: AuthInfo = Depends(),
):
    maskinporten_client = MaskinportenClient(env)

    try:
        client = maskinporten_client.request("GET", ["idporten:dcr.read"], client_id)
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            raise HTTPException(404, f"No client with ID {client_id}")
        raise

    jwk = jwk_from_key(generate_key(), client["client_name"])

    logger.debug(f"Registering new key with id {jwk['kid']} for client {client_id}")

    jwks = maskinporten_client.request(
        "POST", ["idporten:dcr.write"], f"{client_id}/jwks", json={"keys": [jwk]}
    )

    return ClientKey(kid=jwks["keys"][0]["kid"])


@router.get(
    "/{env}/{client_id}/keys",
    dependencies=[Depends(authorize(scope="okdata:maskinporten-client:create"))],
    status_code=status.HTTP_200_OK,
    response_model=list[ClientKeyMetadata],
    responses=error_message_models(
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
    ),
)
def list_client_keys(env: str, client_id: str):
    maskinporten_client = MaskinportenClient(env)
    try:
        jwks = maskinporten_client.request(
            "GET", ["idporten:dcr.read"], f"{client_id}/jwks"
        )
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            raise HTTPException(404, f"No client with ID {client_id}")
        raise

    return [
        ClientKeyMetadata(kid=key["kid"], client_id=client_id)
        for key in jwks.get("keys", [])
    ]
