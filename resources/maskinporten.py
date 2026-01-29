import logging
import os
from datetime import datetime, timezone

import requests
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, Path, status
from fastapi.responses import JSONResponse
from okdata.aws.logging import log_exception
from pydantic import ValidationError

from models import (
    ClientIn,
    ClientKeyMetadata,
    ClientType,
    CreateClientKeyIn,
    CreateClientKeyOut,
    DeleteMaskinportenClientIn,
    DeleteMaskinportenClientOut,
    IdPortenClientIn,
    MaskinportenClientIn,
    MaskinportenClientOut,
    MaskinportenEnvironment,
    Organization,
)
from maskinporten_api.audit import audit_log, audit_notify
from maskinporten_api.auto_rotate import disable_auto_rotate, enable_auto_rotate
from maskinporten_api.keys import create_key
from maskinporten_api.maskinporten_client import (
    KeyNotFoundError,
    MaskinportenClient,
    TooManyKeysError,
    UnsupportedEnvironmentError,
    UnsupportedOrganizationError,
)
from maskinporten_api.permissions import (
    client_resource_name,
    create_okdata_permissions,
    delete_okdata_permissions,
    get_team,
    get_user_permissions,
)
from maskinporten_api.ssm import (
    AssumeRoleAccessDeniedError,
    ForeignAccountSecretsClient,
)
from maskinporten_api.util import getenv, sanitize
from resources.authorizer import AuthInfo, authorize, ServiceClient
from resources.errors import (
    error_message_models,
    ErrorResponse,
    pydantic_error_to_str,
)

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
        status.HTTP_500_INTERNAL_SERVER_ERROR,
    ),
)
def create_client(
    body: ClientIn,
    auth_info: AuthInfo = Depends(),
    service_client: ServiceClient = Depends(),
):
    authorize(auth_info, scope="maskinporten:client:create")

    try:
        client_model = (
            IdPortenClientIn
            if body.client_type == ClientType.idporten
            else MaskinportenClientIn
        )
        client_in = client_model(**body.model_dump())
    except ValidationError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "message": "Invalid data provided for client type: "
                + "\n".join(map(pydantic_error_to_str, exc.errors())),
            },
        )

    try:
        team = get_team(
            client_in.team_id,
            auth_info.bearer_token,
            has_role="origo-team",
        )
        if not team.get("is_member"):
            raise ErrorResponse(status.HTTP_403_FORBIDDEN, "Forbidden")
    except requests.RequestException as e:
        log_exception(e)
        if e.response.status_code == status.HTTP_403_FORBIDDEN:
            raise ErrorResponse(status.HTTP_403_FORBIDDEN, "Forbidden")
        raise ErrorResponse(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error"
        )

    team_name = team["name"]

    logger.debug(
        sanitize(
            f"Creating new {client_in.client_type} ({client_in.provider}) "
            "client for team '{team_name}' in {client_in.env}."
        )
    )

    try:
        maskinporten_client = MaskinportenClient(client_in.org, client_in.env)
    except UnsupportedEnvironmentError as e:
        raise ErrorResponse(status.HTTP_400_BAD_REQUEST, str(e))

    new_client = (
        maskinporten_client.create_idporten_client(
            client_in.env,
            team_name,
            client_in.provider,
            client_in.integration,
            client_in.client_uri,
            client_in.redirect_uris,
            client_in.post_logout_redirect_uris,
            client_in.frontchannel_logout_uri,
        ).json()
        if body.client_type == ClientType.idporten
        else maskinporten_client.create_maskinporten_client(
            client_in.env,
            team_name,
            client_in.provider,
            client_in.integration,
            client_in.scopes,
        ).json()
    )

    new_client_id = new_client["client_id"]
    new_client_scopes = new_client["scopes"]
    resource_name = client_resource_name(client_in.env, new_client_id)

    try:
        create_okdata_permissions(
            resource_name=resource_name,
            team_name=team_name,
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
        item_id=resource_name,
        action="create",
        user=auth_info.principal_id,
        scopes=new_client_scopes,
    )
    audit_notify(
        "Client created", new_client["client_name"], client_in.env, new_client_scopes
    )

    return MaskinportenClientOut.model_validate({**new_client, "org": client_in.org})


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

    clients = []

    for org in Organization:
        try:
            maskinporten_client = MaskinportenClient(org, env)
        except (UnsupportedEnvironmentError, UnsupportedOrganizationError) as e:
            raise ErrorResponse(status.HTTP_400_BAD_REQUEST, str(e))

        for client in maskinporten_client.get_clients().json():
            permission = user_permissions.get(
                client_resource_name(env, client["client_id"])
            )
            if permission and required_scope in permission["scopes"]:
                clients.append(
                    MaskinportenClientOut.model_validate(
                        {**client, "org": org},
                        from_attributes=True,
                    )
                )

    return clients


@router.post(
    "/{env}/{client_id}/delete",
    status_code=status.HTTP_200_OK,
    response_model=DeleteMaskinportenClientOut,
    responses=error_message_models(
        status.HTTP_400_BAD_REQUEST,
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
        status.HTTP_422_UNPROCESSABLE_CONTENT,
    ),
)
def delete_client(  # noqa: C901
    env: MaskinportenEnvironment,
    body: DeleteMaskinportenClientIn,
    client_id: str = Path(..., pattern=r"^[0-9a-f-]+$"),
    auth_info: AuthInfo = Depends(),
    service_client: ServiceClient = Depends(),
):
    resource_name = client_resource_name(env, client_id)

    authorize(
        auth_info,
        scope="maskinporten:client:write",
        resource=resource_name,
    )

    try:
        maskinporten_client = MaskinportenClient(body.org, env)
    except UnsupportedEnvironmentError as e:
        raise ErrorResponse(status.HTTP_400_BAD_REQUEST, str(e))

    try:
        client = maskinporten_client.get_client(client_id).json()
    except requests.HTTPError as e:
        if e.response.status_code == status.HTTP_404_NOT_FOUND:
            raise ErrorResponse(
                status.HTTP_404_NOT_FOUND, f"No client with ID {client_id}"
            )
        raise

    try:
        # Search for active keys associated with client
        existing_jwks = (
            maskinporten_client.get_client_keys(client_id).json().get("keys", [])
        )

        if len(existing_jwks) > 0:
            raise ErrorResponse(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                f"Client {client_id} cannot be deleted due to active keys associated with client.",
            )
    except requests.HTTPError:
        raise ErrorResponse(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Client {client_id} cannot be deleted due to internal server error.",
        )

    send_to_aws = body and body.aws_account and body.aws_region
    if send_to_aws:
        try:
            secrets_client = ForeignAccountSecretsClient(
                body.aws_account, body.aws_region, client_id
            )
        except AssumeRoleAccessDeniedError as e:
            raise ErrorResponse(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e))

    logger.debug(sanitize(f"Deleting maskinporten client {client_id}"))

    try:
        maskinporten_client.delete_client(client_id)
    except requests.HTTPError:
        raise ErrorResponse(
            status.HTTP_500_INTERNAL_SERVER_ERROR, f"No client with ID {client_id}"
        )

    deleted_ssm_params = []
    if send_to_aws:
        try:
            deleted_ssm_params = secrets_client.delete_secrets(
                ["key.json", "key_id", "keystore", "key_alias", "key_password"]
            )
        except ClientError:
            # Secrets deletion failed. The client is informed by the returned
            # `deleted_ssm_params` being empty.
            pass

    try:
        delete_okdata_permissions(
            resource_name=resource_name,
            auth_header=service_client.authorization_header,
        )
    except requests.RequestException as e:
        # Permission deletion failed. Don't bother the client about this, but
        # log it for our sake still.
        log_exception(e)

    logger.debug(sanitize(f"Disabling key rotation for {client_id}"))
    disable_auto_rotate(client_id, env)

    audit_log(
        item_id=resource_name,
        action="delete",
        user=auth_info.principal_id,
    )
    audit_notify("Client deleted", client["client_name"], env, client["scopes"])

    return DeleteMaskinportenClientOut(
        client_id=client_id,
        deleted_ssm_params=deleted_ssm_params,
    )


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
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        status.HTTP_500_INTERNAL_SERVER_ERROR,
    ),
)
def create_client_key(
    body: CreateClientKeyIn,
    env: MaskinportenEnvironment,
    client_id: str = Path(..., pattern=r"^[0-9a-f-]+$"),
    auth_info: AuthInfo = Depends(),
):
    resource_name = client_resource_name(env, client_id)

    authorize(
        auth_info,
        scope="maskinporten:client:write",
        resource=resource_name,
    )

    try:
        maskinporten_client = MaskinportenClient(body.org, env)
    except UnsupportedEnvironmentError as e:
        raise ErrorResponse(status.HTTP_400_BAD_REQUEST, str(e))

    try:
        client = maskinporten_client.get_client(client_id).json()
    except requests.HTTPError as e:
        if e.response.status_code == status.HTTP_404_NOT_FOUND:
            raise ErrorResponse(
                status.HTTP_404_NOT_FOUND, f"No client with ID {client_id}"
            )
        raise

    send_to_aws = body.destination_aws_account and body.destination_aws_region

    if send_to_aws:
        try:
            secrets_client = ForeignAccountSecretsClient(
                body.destination_aws_account,
                body.destination_aws_region,
                client_id,
            )
        except AssumeRoleAccessDeniedError as e:
            raise ErrorResponse(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e))

    key = create_key(
        int(
            getenv(
                "KEY_UNDER_ROTATION_EXPIRATION_DAYS"
                if body.enable_auto_rotate
                else "KEY_DEFAULT_EXPIRATION_DAYS"
            )
        )
    )
    kid = key.jwk["kid"]
    logger.debug(
        sanitize(f"Registering new key with id {kid} for client {client_id}"),
    )

    try:
        maskinporten_client.create_client_key(client_id, key.jwk).json()
    except TooManyKeysError as e:
        raise ErrorResponse(status.HTTP_409_CONFLICT, str(e))

    ssm_params = None
    client_name = client["client_name"]

    if send_to_aws:
        try:
            ssm_params = secrets_client.send_key_to_aws(key, env, client_name)
            if body.enable_auto_rotate:
                logger.debug(
                    sanitize(f"Enabling key rotation for {client_id}"),
                )
                enable_auto_rotate(
                    client_id,
                    body.org,
                    env,
                    body.destination_aws_account,
                    body.destination_aws_region,
                    client_name,
                )
        except ClientError as e:
            # Secrets injection failed somehow. Retract the newly created key.
            log_exception(e)
            maskinporten_client.delete_client_key(client_id, kid)
            raise ErrorResponse(
                status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error"
            )

    audit_log(
        item_id=resource_name,
        action="add-key",
        user=auth_info.principal_id,
        key_id=kid,
    )
    audit_notify("Client key added", client_name, env, client["scopes"])

    return CreateClientKeyOut(
        kid=kid,
        expires=datetime.fromtimestamp(int(key.jwk["exp"]), tz=timezone.utc),
        ssm_params=ssm_params,
        keystore=None if send_to_aws else key.keystore,
        key_alias=None if send_to_aws else key.alias,
        key_password=None if send_to_aws else key.password,
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
    client_id: str = Path(..., pattern=r"^[0-9a-f-]+$"),
    key_id: str = Path(...),
    auth_info: AuthInfo = Depends(),
):
    resource_name = client_resource_name(env, client_id)

    authorize(
        auth_info,
        scope="maskinporten:client:write",
        resource=resource_name,
    )

    client = None

    for org in Organization:
        maskinporten_client = MaskinportenClient(org, env)

        try:
            client = maskinporten_client.get_client(client_id).json()
            break
        except requests.HTTPError as e:
            if e.response.status_code in (
                status.HTTP_403_FORBIDDEN,
                status.HTTP_404_NOT_FOUND,
            ):
                continue
            raise

    if client is None:
        raise ErrorResponse(status.HTTP_404_NOT_FOUND, f"No client with ID {client_id}")

    logger.debug(sanitize(f"Deleting key {key_id} from client {client_id}"))

    try:
        maskinporten_client.delete_client_key(client_id, key_id)
    except KeyNotFoundError as e:
        raise ErrorResponse(status.HTTP_404_NOT_FOUND, str(e))

    audit_log(
        item_id=resource_name,
        action="remove-key",
        user=auth_info.principal_id,
        key_id=key_id,
    )
    audit_notify("Client key removed", client["client_name"], env, client["scopes"])


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
    client_id: str = Path(..., pattern=r"^[0-9a-f-]+$"),
    auth_info: AuthInfo = Depends(),
):
    authorize(
        auth_info,
        scope="maskinporten:client:read",
        resource=client_resource_name(env, client_id),
    )

    jwks = None

    for org in Organization:
        maskinporten_client = MaskinportenClient(org, env)

        try:
            jwks = maskinporten_client.get_client_keys(client_id).json()
            break
        except requests.HTTPError as e:
            if e.response.status_code in (
                status.HTTP_403_FORBIDDEN,
                status.HTTP_404_NOT_FOUND,
            ):
                continue
            raise

    if jwks is None:
        raise ErrorResponse(status.HTTP_404_NOT_FOUND, f"No client with ID {client_id}")

    return [
        ClientKeyMetadata(
            kid=key["kid"],
            client_id=client_id,
            expires=datetime.fromtimestamp(int(key["exp"]), tz=timezone.utc),
        )
        for key in jwks.get("keys", [])
    ]
