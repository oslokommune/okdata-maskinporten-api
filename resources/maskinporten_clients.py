import logging
import os
import re
from datetime import datetime, timedelta

import requests
from fastapi import APIRouter, Depends, status

from models import (
    ClientKeyMetadata,
    CreateClientKeyIn,
    CreateClientKeyOut,
    DeleteClientKeyOut,
    MaskinportenClientIn,
    MaskinportenClientOut,
    MaskinportenEnvironment,
)
from maskinporten_api.audit import audit_log
from maskinporten_api.keys import (
    generate_key,
    jwk_from_key,
    pkcs12_from_key,
    generate_password,
)
from maskinporten_api.maskinporten_client import (
    KeyNotFoundError,
    MaskinportenClient,
    TooManyKeysError,
    UnsupportedEnvironmentError,
)
from maskinporten_api.permissions import create_okdata_permissions
from maskinporten_api.ssm import (
    SendSecretsService,
    Secrets,
    AssumeRoleAccessDeniedException,
)
from maskinporten_api.util import sanitize
from resources.authorizer import AuthInfo, authorize, ServiceClient
from resources.errors import error_message_models, ErrorResponse

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
    service_client: ServiceClient = Depends(),
):
    logger.debug(
        sanitize(
            f"Creating new client '{body.name}' in {body.env} with scopes {body.scopes}"
        )
    )
    try:
        new_client = MaskinportenClient(body.env).create_client(body)
    except UnsupportedEnvironmentError as e:
        raise ErrorResponse(status.HTTP_400_BAD_REQUEST, str(e))

    # TODO: Roll back created client if permission creation fails.
    create_okdata_permissions(
        resource_name=f"okdata:maskinporten-client:{body.env}-{new_client['client_id']}",
        owner_principal_id=auth_info.principal_id,
        auth_header=service_client.authorization_header,
    )

    audit_log(
        item_id=new_client["client_id"],
        item_type="client",
        env=body.env,
        action="create",
        user=auth_info.principal_id,
        scopes=new_client["scopes"],
    )

    return MaskinportenClientOut.parse_obj(new_client)


@router.get(
    "/{env}",
    dependencies=[Depends(authorize(scope="okdata:maskinporten-client:create"))],
    status_code=status.HTTP_200_OK,
    response_model=list[MaskinportenClientOut],
    responses=error_message_models(
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    ),
)
def list_clients(env: MaskinportenEnvironment, auth_info: AuthInfo = Depends()):
    try:
        maskinporten_client = MaskinportenClient(env)
    except UnsupportedEnvironmentError as e:
        raise ErrorResponse(status.HTTP_400_BAD_REQUEST, str(e))

    return [
        MaskinportenClientOut.parse_obj(c) for c in maskinporten_client.get_clients()
    ]


@router.post(
    "/{env}/{client_id}/keys",
    dependencies=[Depends(authorize(scope="okdata:maskinporten-client:create"))],
    status_code=status.HTTP_201_CREATED,
    response_model=CreateClientKeyOut,
    responses=error_message_models(
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
        status.HTTP_422_UNPROCESSABLE_ENTITY,
    ),
)
def create_client_key(
    env: MaskinportenEnvironment,
    client_id: str,
    body: CreateClientKeyIn,
    auth_info: AuthInfo = Depends(),
):
    if not re.fullmatch("[0-9a-f-]+", client_id):
        raise ErrorResponse(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Invalid client ID: {client_id}",
        )

    try:
        maskinporten_client = MaskinportenClient(env)
    except UnsupportedEnvironmentError as e:
        raise ErrorResponse(status.HTTP_400_BAD_REQUEST, str(e))

    send_secrets_service = SendSecretsService()

    try:
        maskinporten_client.get_client(client_id)
    except requests.HTTPError as e:
        if e.response.status_code == status.HTTP_404_NOT_FOUND:
            raise ErrorResponse(
                status.HTTP_404_NOT_FOUND, f"No client with ID {client_id}"
            )
        raise

    key = generate_key()
    jwk = jwk_from_key(key)
    key_id = jwk["kid"]

    logger.debug(
        sanitize(f"Registering new key with id {key_id} for client {client_id}")
    )

    key_password = generate_password(pw_length=32)

    try:
        send_secrets_service.send_secrets(
            secrets=Secrets(
                keystore=pkcs12_from_key(key, key_password),
                key_id=key_id,
                key_password=key_password,
            ),
            maskinporten_client_id=client_id,
            destination_aws_account_id=body.destination_aws_account,
            destination_aws_region=body.destination_aws_region,
        )
    except AssumeRoleAccessDeniedException as e:
        raise ErrorResponse(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))

    try:
        jwks = maskinporten_client.create_client_key(client_id, jwk)
    except TooManyKeysError as e:
        # TODO: We should revert the secrets injected to AWS here. Actually we
        #       should do that if any exception is raised.
        raise ErrorResponse(status.HTTP_409_CONFLICT, str(e))

    kid = jwks["keys"][0]["kid"]

    audit_log(
        item_id=kid,
        item_type="key",
        env=env,
        action="create",
        user=auth_info.principal_id,
        client_id=client_id,
    )

    return CreateClientKeyOut(kid=kid)


@router.delete(
    "/{env}/{client_id}/keys/{key_id}",
    dependencies=[Depends(authorize(scope="okdata:maskinporten-client:create"))],
    status_code=status.HTTP_200_OK,
    response_model=DeleteClientKeyOut,
    responses=error_message_models(
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
        status.HTTP_422_UNPROCESSABLE_ENTITY,
    ),
)
def delete_client_key(
    env: MaskinportenEnvironment,
    client_id: str,
    key_id: str,
    auth_info: AuthInfo = Depends(),
):
    if not re.fullmatch("[0-9a-f-]+", client_id):
        raise ErrorResponse(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Invalid client ID: {client_id}",
        )

    try:
        maskinporten_client = MaskinportenClient(env)
    except UnsupportedEnvironmentError as e:
        raise ErrorResponse(status.HTTP_400_BAD_REQUEST, str(e))

    try:
        maskinporten_client.get_client(client_id)
    except requests.HTTPError as e:
        if e.response.status_code == status.HTTP_404_NOT_FOUND:
            raise ErrorResponse(
                status.HTTP_404_NOT_FOUND, f"No client with ID {client_id}"
            )
        raise

    logger.debug(sanitize(f"Deleting key {key_id} from client {client_id}"))

    try:
        maskinporten_client.delete_client_key(client_id, key_id)
    except KeyNotFoundError as e:
        raise ErrorResponse(status.HTTP_404_NOT_FOUND, str(e))

    audit_log(
        item_id=key_id,
        item_type="key",
        env=env,
        action="delete",
        user=auth_info.principal_id,
        client_id=client_id,
    )

    # TODO: We should also delete the key from SSM. Inform the client with the
    #       `deleted_from_ssm` field whether this was done or not.
    return DeleteClientKeyOut(deleted_from_ssm=False)


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
def list_client_keys(env: MaskinportenEnvironment, client_id: str):
    try:
        maskinporten_client = MaskinportenClient(env)
    except UnsupportedEnvironmentError as e:
        raise ErrorResponse(status.HTTP_400_BAD_REQUEST, str(e))

    try:
        jwks = maskinporten_client.get_client_keys(client_id)
    except requests.HTTPError as e:
        if e.response.status_code == status.HTTP_404_NOT_FOUND:
            raise ErrorResponse(
                status.HTTP_404_NOT_FOUND, f"No client with ID {client_id}"
            )
        raise

    if "keys" not in jwks:
        return []

    created = jwks["created"]
    last_updated = jwks["last_updated"]
    expires = datetime.fromisoformat(created) + timedelta(days=365)

    return [
        ClientKeyMetadata(
            kid=key["kid"],
            client_id=client_id,
            created=created,
            expires=expires,
            last_updated=last_updated,
        )
        for key in jwks["keys"]
    ]
