import os

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


def resource_authorizer() -> ResourceAuthorizer:
    return ResourceAuthorizer()


http_bearer = HTTPBearer(scheme_name="Keycloak token")


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


def authorize(scope: str, resource: str = None):
    def _verify_permission(
        auth_info: AuthInfo = Depends(),
        resource_authorizer: ResourceAuthorizer = Depends(resource_authorizer),
    ):
        if not resource_authorizer.has_access(auth_info.bearer_token, scope, resource):
            raise ErrorResponse(403, "Forbidden")

    return _verify_permission
