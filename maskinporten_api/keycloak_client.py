from keycloak import KeycloakOpenID
from .keycloak_config import KeycloakConfig


def setup_keycloak_client(keycloak_config: KeycloakConfig):
    return KeycloakOpenID(
        server_url=f"{keycloak_config.server_url}/auth/",
        realm_name=keycloak_config.realm_name,
        client_id=keycloak_config.client_id,
        client_secret_key=keycloak_config.client_secret,
    )
