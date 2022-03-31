import base64
import dataclasses

import requests
from OpenSSL import crypto
from botocore.exceptions import ClientError

from maskinporten_api.jwt_client import JWTAuthClient, JWTConfig
from maskinporten_api.ssm import get_secret
from maskinporten_api.util import getenv
from models import MaskinportenClientIn, MaskinportenEnvironment


class UnsupportedEnvironmentError(Exception):
    def __init__(self, env):
        super().__init__(f"Maskinporten environment '{env}' is not supported")


@dataclasses.dataclass
class EnvConfig:
    name: MaskinportenEnvironment
    idporten_oidc_wellknown: str
    maskinporten_clients_endpoint: str

    def maskinporten_admin_client_id(self):
        try:
            return getenv(f"MASKINPORTEN_ADMIN_CLIENT_ID_{self.name.upper()}")
        except ClientError:
            raise UnsupportedEnvironmentError(self.name)

    def certificate(self):
        try:
            return get_secret(
                f"/dataplatform/maskinporten/origo-certificate-{self.name}"
            )
        except ClientError:
            raise UnsupportedEnvironmentError(self.name)

    def certificate_password(self):
        try:
            return get_secret(
                f"/dataplatform/maskinporten/origo-certificate-password-{self.name}"
            )
        except ClientError:
            raise UnsupportedEnvironmentError(self.name)


_ENV_CONFIGS = [
    EnvConfig(
        MaskinportenEnvironment.test.value,
        "https://oidc-ver2.difi.no/idporten-oidc-provider/.well-known/openid-configuration",
        "https://integrasjon-ver2.difi.no/clients/",
    ),
    EnvConfig(
        MaskinportenEnvironment.prod.value,
        "https://oidc.difi.no/idporten-oidc-provider/.well-known/openid-configuration",
        "https://integrasjon.difi.no/clients/",
    ),
]


def env_config(env):
    """Return the configuration for environment `env`."""
    try:
        return next(e for e in _ENV_CONFIGS if e.name == env)
    except StopIteration:
        raise UnsupportedEnvironmentError(env)


class MaskinportenClient:
    def __init__(self, env):
        config = env_config(env)
        p12 = crypto.load_pkcs12(
            base64.b64decode(config.certificate()),
            config.certificate_password().encode("utf-8"),
        )
        conf = JWTConfig(
            issuer=config.maskinporten_admin_client_id(),
            certificate=p12.get_certificate(),
            private_key=p12.get_privatekey(),
        )
        self.client = JWTAuthClient(conf, config.idporten_oidc_wellknown)
        self.base_url = config.maskinporten_clients_endpoint

    def create_client(self, client: MaskinportenClientIn):
        return self._request(
            "POST",
            ["idporten:dcr.write"],
            json={
                "client_name": client.name,
                "description": client.description,
                "scopes": client.scopes,
                "token_endpoint_auth_method": "private_key_jwt",
                "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
                "integration_type": "maskinporten",
                "application_type": "web",
            },
        )

    def get_client(self, client_id: str):
        return self._request("GET", ["idporten:dcr.read"], client_id)

    def get_clients(self):
        return self._request("GET", ["idporten:dcr.read"])

    def create_client_key(self, client_id: str, jwk: dict):
        return self._request(
            "POST", ["idporten:dcr.write"], f"{client_id}/jwks", json={"keys": [jwk]}
        )

    def get_client_keys(self, client_id: str):
        return self._request("GET", ["idporten:dcr.read"], f"{client_id}/jwks")

    def _request(self, method, scopes, path="", json=None):
        access_token = self.client.get_access_token(scopes)

        response = requests.request(
            method,
            f"{self.base_url}{path}",
            headers={
                "Accept": "*/*",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
            json=json,
        )
        response.raise_for_status()

        return response.json()
