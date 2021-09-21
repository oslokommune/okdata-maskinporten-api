import logging
import os

import requests
from fastapi import APIRouter, Depends, HTTPException, status, Form

from models import (
    MaskinportenClientIn,
    MaskinportenClientOut,
    ClientKey,
    ClientKeyMetadata,
)
from maskinporten_api.keys import generate_key, jwk_from_key
from maskinporten_api.maskinporten_client import MaskinportenClient
from maskinporten_api.ssm import SSMService, Secrets
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
    destination_aws_account: str = Form(...),
    destination_aws_region: str = Form(...),
    auth_info: AuthInfo = Depends(),
):
    maskinporten_client = MaskinportenClient(env)
    ssm_service = SSMService()

    try:
        client = maskinporten_client.get_client(client_id)
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            raise HTTPException(404, f"No client with ID {client_id}")
        raise

    jwk = jwk_from_key(generate_key(), client["client_name"])

    logger.debug(f"Registering new key with id {jwk['kid']} for client {client_id}")

    jwks = maskinporten_client.create_client_key(client_id, jwk)

    ssm_service.send_secrets(
        secrets=Secrets(keystore="TODO", key_id="TODO", key_password="TODO"),
        maskinporten_client_id=client_id,
        destination_aws_account_id=destination_aws_account,
        destination_aws_region=destination_aws_region,
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
        jwks = maskinporten_client.get_client_keys(client_id)
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            raise HTTPException(404, f"No client with ID {client_id}")
        raise

    return [
        ClientKeyMetadata(kid=key["kid"], client_id=client_id)
        for key in jwks.get("keys", [])
    ]
