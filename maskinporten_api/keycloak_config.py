import os
from dataclasses import dataclass
import boto3


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


class SSMClient:
    def __init__(self):
        self.client = boto3.client("ssm", region_name=os.environ["AWS_REGION"])

    def get_ssm_parameters(self, parameter_names, with_decryption=False):
        parameters = self.client.get_parameters(
            Names=parameter_names, WithDecryption=with_decryption
        )["Parameters"]
        parameters_dict = {}
        for parameter in parameters:
            parameters_dict[parameter["Name"]] = parameter["Value"]

        return parameters_dict
