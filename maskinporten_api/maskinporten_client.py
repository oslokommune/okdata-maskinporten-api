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


class TooManyKeysError(Exception):
    def __init__(self, client_id, max_keys):
        super().__init__(
            f"Client '{client_id}' already has the maximum number of registered keys: {max_keys}"
        )


class KeyNotFoundError(Exception):
    def __init__(self, client_id, key_id):
        super().__init__(f"Key '{key_id}' not found for client '{client_id}'")


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
    # The maximum number of keys that a Maskinporten client will hold. This is
    # a restriction in Maskinporten itself.
    MAX_KEYS = 5

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

    def delete_client(self, client_id: str):
        return self._request("DELETE", ["idporten:dcr.write"], client_id)

    def create_client_key(self, client_id: str, jwk: dict):
        existing_jwks = self.get_client_keys(client_id).json().get("keys", [])

        if len(existing_jwks) >= self.MAX_KEYS:
            raise TooManyKeysError(client_id, self.MAX_KEYS)

        return self._request(
            "POST",
            ["idporten:dcr.write"],
            f"{client_id}/jwks",
            # XXX: We need to send every existing key together with the new
            # one, otherwise all the existing keys are deleted. This comes with
            # an additional quirk: The expiration date of the existing keys are
            # renewed as well... Digdir is looking into a fix for this.
            json={"keys": [jwk, *existing_jwks]},
        )

    def delete_client_key(self, client_id, key_id):
        existing_jwks = self.get_client_keys(client_id).json().get("keys", [])
        updated_jwks = [jwk for jwk in existing_jwks if jwk["kid"] != key_id]

        if len(existing_jwks) == len(updated_jwks):
            raise KeyNotFoundError(client_id, key_id)

        if len(updated_jwks) == 0:
            # When deleting the last key, we need to DELETE instead of POST-ing
            # an empty `keys` object.
            return self._request(
                "DELETE",
                ["idporten:dcr.write"],
                f"{client_id}/jwks",
            )

        return self._request(
            "POST",
            ["idporten:dcr.write"],
            f"{client_id}/jwks",
            json={"keys": updated_jwks},
        )

    def get_client_keys(self, client_id: str):
        return self._request(
            "GET",
            ["idporten:dcr.read"],
            f"{client_id}/jwks",
        )

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

        return response
