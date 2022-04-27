import logging
import os
import re
from datetime import datetime, timedelta

import requests
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, Path, status
from okdata.aws.logging import log_exception

from models import (
    ClientKeyMetadata,
    CreateClientKeyIn,
    CreateClientKeyOut,
    MaskinportenClientIn,
    MaskinportenClientOut,
    DeleteMaskinportenClientOut,
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
from maskinporten_api.permissions import create_okdata_permissions, get_user_permissions
from maskinporten_api.ssm import (
    AssumeRoleAccessDeniedError,
    ForeignAccountSecretsClient,
)
from maskinporten_api.util import sanitize
from resources.authorizer import AuthInfo, authorize, ServiceClient
from resources.errors import error_message_models, ErrorResponse

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))


router = APIRouter()


@router.post(
    "",
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
    authorize(auth_info, scope="maskinporten:client:create")

    # TODO: Look up the actual team name here instead of using the (unreadable)
    #       team ID once permission-api is extended to support it (T#179).
    team_name = body.team_id

    logger.debug(
        sanitize(
            f"Creating new {body.provider} client for team '{team_name}' in "
            "{body.env} with scopes {body.scopes}"
        )
    )
    try:
        maskinporten_client = MaskinportenClient(body.env)
    except UnsupportedEnvironmentError as e:
        raise ErrorResponse(status.HTTP_400_BAD_REQUEST, str(e))

    new_client = maskinporten_client.create_client(
        team_name, body.provider, body.integration, body.scopes
    ).json()
    new_client_id = new_client["client_id"]

    try:
        create_okdata_permissions(
            resource_name=f"maskinporten:client:{body.env}-{new_client_id}",
            owner_principal_id=auth_info.principal_id,
            auth_header=service_client.authorization_header,
        )
    except requests.RequestException as e:
        # Permission creation failed. Retract the created Maskinporten client.
        log_exception(e)
        maskinporten_client.delete_client(new_client_id)
        raise ErrorResponse(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error"
        )

    audit_log(
        item_id=new_client_id,
        item_type="client",
        env=body.env,
        action="create",
        user=auth_info.principal_id,
        scopes=new_client["scopes"],
    )

    return MaskinportenClientOut.parse_obj(new_client)


@router.get(
    "/{env}",
    status_code=status.HTTP_200_OK,
    response_model=list[MaskinportenClientOut],
    responses=error_message_models(
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    ),
)
def list_clients(env: MaskinportenEnvironment, auth_info: AuthInfo = Depends()):
    required_scope = "maskinporten:client:read"
    authorize(auth_info, scope=required_scope)

    try:
        user_permissions = get_user_permissions(auth_info.bearer_token)
    except requests.RequestException as e:
        log_exception(e)
        raise ErrorResponse(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error"
        )

    try:
        maskinporten_client = MaskinportenClient(env)
    except UnsupportedEnvironmentError as e:
        raise ErrorResponse(status.HTTP_400_BAD_REQUEST, str(e))

    clients = []

    for client in maskinporten_client.get_clients().json():
        resource_name = f"maskinporten:client:{env}-{client['client_id']}"

        permission = user_permissions.get(resource_name)

        if permission and required_scope in permission["scopes"]:
            clients.append(MaskinportenClientOut.parse_obj(client))

    return clients


@router.delete(
    "/{env}/{client_id}",
    status_code=status.HTTP_200_OK,
    response_model=DeleteMaskinportenClientOut,
    responses=error_message_models(
        status.HTTP_400_BAD_REQUEST,
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
        status.HTTP_422_UNPROCESSABLE_ENTITY,
    ),
)
def delete_client(
        env: MaskinportenEnvironment,
        client_id: str = Path(..., regex=r"^[0-9a-f-]+$"),
        auth_info: AuthInfo = Depends(),
):
    authorize(
        auth_info,
        scope="maskinporten:client:write",
        resource=f"maskinporten:client:{env}-{client_id}",
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

    try:
        # Search for active keys associated with client
        existing_jwks = self.get_client_keys(client_id).json().get("keys", [])

        if len(existing_jwks) > 0:
            raise ErrorResponse(
                status.HTTP_422_UNPROCESSABLE_ENTITY, f"Client {client_id} cannot be deleted due to active keys associated with client."
            )
    except requests.HTTPError as e:
        if e.response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
            raise ErrorResponse(
                status.HTTP_500_INTERNAL_SERVER_ERROR, f"Client {client_id} cannot be deleted due to internal server error."
            )
        raise

    logger.debug(sanitize(f"Deleting maskinporten client {client_id}"))

    try:
        maskinporten_client.delete_client(client_id)
    except requests.HTTPError as e:
        if e.response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
            raise ErrorResponse(
                status.HTTP_404_NOT_FOUND, f"No client with ID {client_id}"
            )

    audit_log(
        item_id=client_id,
        item_type="client",
        env=env,
        action="delete",
        user=auth_info.principal_id,
    )

    # TODO: We should also delete resource from keycloak that was created along with client creation
    return DeleteMaskinportenClientOut(client_id)


@router.post(
    "/{env}/{client_id}/keys",
    status_code=status.HTTP_201_CREATED,
    response_model=CreateClientKeyOut,
    responses=error_message_models(
        status.HTTP_400_BAD_REQUEST,
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
        status.HTTP_409_CONFLICT,
        status.HTTP_422_UNPROCESSABLE_ENTITY,
        status.HTTP_500_INTERNAL_SERVER_ERROR,
    ),
)
def create_client_key(
    body: CreateClientKeyIn,
    env: MaskinportenEnvironment,
    client_id: str = Path(..., regex=r"^[0-9a-f-]+$"),
    auth_info: AuthInfo = Depends(),
):
    authorize(
        auth_info,
        scope="maskinporten:client:write",
        resource=f"maskinporten:client:{env}-{client_id}",
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

    key = generate_key()
    jwk = jwk_from_key(key)
    key_id = jwk["kid"]

    logger.debug(
        sanitize(f"Registering new key with id {key_id} for client {client_id}")
    )

    key_password = generate_password(pw_length=32)
    keystore = pkcs12_from_key(key, key_password)
    ssm_params = None
    send_to_aws = body.destination_aws_account and body.destination_aws_region

    if send_to_aws:
        try:
            secrets_client = ForeignAccountSecretsClient(
                body.destination_aws_account,
                body.destination_aws_region,
                client_id,
            )
        except AssumeRoleAccessDeniedError as e:
            raise ErrorResponse(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))

    try:
        maskinporten_client.create_client_key(client_id, jwk).json()
    except TooManyKeysError as e:
        raise ErrorResponse(status.HTTP_409_CONFLICT, str(e))

    if send_to_aws:
        try:
            ssm_params = secrets_client.send_secrets(
                {
                    "keystore": keystore,
                    "key_id": key_id,
                    "key_password": key_password,
                }
            )
        except ClientError as e:
            # Secrets injection failed somehow. Retract the newly created key.
            log_exception(e)
            maskinporten_client.delete_client_key(client_id, key_id)
            raise ErrorResponse(
                status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error"
            )

    audit_log(
        item_id=client_id,
        item_type="client",
        env=env,
        action="add-key",
        user=auth_info.principal_id,
        key_id=key_id,
    )

    return CreateClientKeyOut(
        kid=key_id,
        ssm_params=ssm_params,
        keystore=None if send_to_aws else keystore,
        key_password=None if send_to_aws else key_password,
    )


@router.delete(
    "/{env}/{client_id}/keys/{key_id}",
    status_code=status.HTTP_200_OK,
    responses=error_message_models(
        status.HTTP_400_BAD_REQUEST,
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
    ),
)
def delete_client_key(
    env: MaskinportenEnvironment,
    client_id: str = Path(..., regex=r"^[0-9a-f-]+$"),
    key_id: str = Path(...),
    auth_info: AuthInfo = Depends(),
):
    authorize(
        auth_info,
        scope="maskinporten:client:write",
        resource=f"maskinporten:client:{env}-{client_id}",
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
        item_id=client_id,
        item_type="client",
        env=env,
        action="remove-key",
        user=auth_info.principal_id,
        key_id=key_id,
    )


@router.get(
    "/{env}/{client_id}/keys",
    status_code=status.HTTP_200_OK,
    response_model=list[ClientKeyMetadata],
    responses=error_message_models(
        status.HTTP_400_BAD_REQUEST,
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
    ),
)
def list_client_keys(
    env: MaskinportenEnvironment,
    client_id: str = Path(..., regex=r"^[0-9a-f-]+$"),
    auth_info: AuthInfo = Depends(),
):
    authorize(
        auth_info,
        scope="maskinporten:client:read",
        resource=f"maskinporten:client:{env}-{client_id}",
    )

    try:
        maskinporten_client = MaskinportenClient(env)
    except UnsupportedEnvironmentError as e:
        raise ErrorResponse(status.HTTP_400_BAD_REQUEST, str(e))

    try:
        jwks = maskinporten_client.get_client_keys(client_id).json()
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
