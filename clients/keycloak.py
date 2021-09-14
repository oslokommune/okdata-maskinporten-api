import os
from dataclasses import dataclass

from keycloak import KeycloakOpenID

from clients.ssm import SSMClient


@dataclass
class KeycloakConfig:
    client_id: str
    client_secret: str
    server_url: str
    realm_name: str


def get_keycloak_config() -> KeycloakConfig:
    ssm_client = SSMClient()

    client_id = "event-stream-api"

    client_secret_ssm_name = f"/dataplatform/{client_id}/keycloak-client-secret"

    server_url_ssm_name = "/dataplatform/shared/keycloak-server-url"

    parameters = ssm_client.get_ssm_parameters(
        [client_secret_ssm_name, server_url_ssm_name],
        with_decryption=True,
    )

    return KeycloakConfig(
        client_id=client_id,
        client_secret=parameters[client_secret_ssm_name],
        server_url=parameters[server_url_ssm_name],
        realm_name=os.environ.get("KEYCLOAK_REALM", "api-catalog"),
    )


def setup_keycloak_client(
    keycloak_config: KeycloakConfig = get_keycloak_config(),
) -> KeycloakOpenID:
    return KeycloakOpenID(
        server_url=f"{keycloak_config.server_url}/auth/",
        realm_name=keycloak_config.realm_name,
        client_id=keycloak_config.client_id,
        client_secret_key=keycloak_config.client_secret,
    )
