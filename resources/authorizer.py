import os
from typing import Optional

from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from keycloak import KeycloakOpenID
from okdata.resource_auth import ResourceAuthorizer

from maskinporten_api.ssm import get_secret
from resources.errors import ErrorResponse


def keycloak_client():
    keycloak_client_id = os.environ["SERVICE_NAME"]
    return KeycloakOpenID(
        server_url=f"{os.environ['KEYCLOAK_SERVER']}/auth/",
        realm_name=os.environ.get("KEYCLOAK_REALM", "api-catalog"),
        client_id=keycloak_client_id,
        client_secret_key=get_secret(
            f"/dataplatform/{keycloak_client_id}/keycloak-client-secret"
        ),
    )


http_bearer = HTTPBearer(scheme_name="KeycloakToken")


class ServiceClient:
    authorization_header: dict

    def __init__(
        self,
        keycloak_client: KeycloakOpenID = Depends(keycloak_client),
    ):
        response = keycloak_client.token(grant_type=["client_credentials"])
        access_token = f"{response['token_type']} {response['access_token']}"
        self.authorization_header = {"Authorization": access_token}


class AuthInfo:
    principal_id: str
    bearer_token: str

    def __init__(
        self,
        authorization: HTTPAuthorizationCredentials = Depends(http_bearer),
        keycloak_client: KeycloakOpenID = Depends(keycloak_client),
    ):
        introspected = keycloak_client.introspect(authorization.credentials)

        if not introspected["active"]:
            raise ErrorResponse(401, "Invalid access token")

        self.principal_id = introspected["username"]
        self.bearer_token = authorization.credentials


def authorize(auth_info: AuthInfo, scope: str, resource: Optional[str] = None):
    resource_authorizer = ResourceAuthorizer()

    has_access = resource_authorizer.has_access(auth_info.bearer_token, scope, resource)

    if not has_access:
        raise ErrorResponse(403, "Forbidden")
