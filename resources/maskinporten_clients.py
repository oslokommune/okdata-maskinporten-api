import logging
import os

import requests
from fastapi import APIRouter, Depends, HTTPException, status

from models import (
    MaskinportenClientIn,
    MaskinportenClientOut,
    ClientKeyOut,
    ClientKeyMetadata,
    ClientKeyIn,
)
from maskinporten_api.keys import (
    generate_key,
    jwk_from_key,
    pkcs12_from_key,
    generate_password,
)
from maskinporten_api.maskinporten_client import MaskinportenClient
from maskinporten_api.ssm import send_secrets, Secrets
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

    new_client = maskinporten_client.create_client(body)

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
    response_model=ClientKeyOut,
    responses=error_message_models(
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
    ),
)
def create_client_key(
    env: str,
    client_id: str,
    body: ClientKeyIn,
    auth_info: AuthInfo = Depends(),
):
    maskinporten_client = MaskinportenClient(env)

    try:
        client = maskinporten_client.get_client(client_id)
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            raise HTTPException(404, f"No client with ID {client_id}")
        raise

    key = generate_key()
    jwk = jwk_from_key(key, client["client_name"])
    key_id = jwk["kid"]

    logger.debug(f"Registering new key with id {key_id} for client {client_id}")

    jwks = maskinporten_client.create_client_key(client_id, jwk)

    key_password = generate_password(pw_length=32)

    # TODO: Find a good procedure for handling the case where `send_secrets` fails
    send_secrets(
        secrets=Secrets(
            keystore=pkcs12_from_key(key, key_password),
            key_id=key_id,
            key_password=key_password,
        ),
        maskinporten_client_id=client_id,
        destination_aws_account_id=body.destination_aws_account,
        destination_aws_region=body.destination_aws_region,
    )

    return ClientKeyOut(kid=jwks["keys"][0]["kid"])


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
        jwks = maskinporten_client.get_client_keys(client_id)
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            raise HTTPException(404, f"No client with ID {client_id}")
        raise

    return [
        ClientKeyMetadata(kid=key["kid"], client_id=client_id)
        for key in jwks.get("keys", [])
    ]
