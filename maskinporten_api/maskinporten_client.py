import base64
import dataclasses
import re
import threading

import requests

from botocore.exceptions import ClientError
from okdata.aws.ssm import get_secret
from cryptography.hazmat.primitives.serialization import pkcs12

from maskinporten_api.jwt_client import JWTAuthClient, JWTConfig
from maskinporten_api.util import getenv
from models import MaskinportenEnvironment


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
    oidc_wellknown: str
    maskinporten_clients_endpoint: str

    def maskinporten_admin_client_id(self):
        try:
            return getenv(f"MASKINPORTEN_ADMIN_CLIENT_ID_{self.name.upper()}")
        except ClientError:
            raise UnsupportedEnvironmentError(self.name)

    def certificate(self):
        try:
            return get_secret(
                f"/dataplatform/maskinporten/origo-certificate-{self.name}.part1"
            ) + get_secret(
                f"/dataplatform/maskinporten/origo-certificate-{self.name}.part2"
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
        "https://test.maskinporten.no/.well-known/oauth-authorization-server",
        "https://api.test.samarbeid.digdir.no/api/v1/clients",
    ),
    EnvConfig(
        MaskinportenEnvironment.prod.value,
        "https://maskinporten.no/.well-known/oauth-authorization-server",
        "https://api.samarbeid.digdir.no/api/v1/clients",
    ),
]


def env_config(env):
    """Return the configuration for environment `env`."""
    try:
        return next(e for e in _ENV_CONFIGS if e.name == env)
    except StopIteration:
        raise UnsupportedEnvironmentError(env)


# The new version of Digdir's Maskinporten API published 2025-05-22 has
# stricter validation checks on client keys; a `use` field is now
# required. This function can be used to patch existing keys that don't have
# `use` fields in a transitional phase. This function can be deleted after some
# time, when all active keys have been migrated.
def _jwk_ensure_use_sig(jwk):
    return {**jwk, "use": "sig"}


class MaskinportenClient:
    # The maximum number of keys that a Maskinporten client will hold. This is
    # a restriction in Maskinporten itself.
    MAX_KEYS = 5

    def __init__(self, env):
        config = env_config(env)

        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            base64.b64decode(config.certificate()),
            config.certificate_password().encode("utf-8"),
        )

        conf = JWTConfig(
            issuer=config.maskinporten_admin_client_id(),
            certificate=certificate,
            private_key=private_key,
        )
        self.client = JWTAuthClient(conf, config.oidc_wellknown)
        self.base_url = config.maskinporten_clients_endpoint
        self._delete_client_key_lock = threading.Lock()

    @staticmethod
    def _slugify_team_name(team_name):
        return (
            re.sub("[^a-zæøå0-9 ]", "", team_name.lower()).strip(" ").replace(" ", "-")
        )

    @classmethod
    def _make_client_name(cls, team_name, provider, integration):
        return f"{cls._slugify_team_name(team_name)}-{provider}-{integration}"

    @staticmethod
    def _make_client_description(team_name, provider, integration):
        return f"{provider.capitalize()}-klient for {integration} ({team_name})"

    def create_maskinporten_client(self, team_name, provider, integration, scopes):
        return self._request(
            "POST",
            ["idporten:dcr.write"],
            json={
                "client_name": self._make_client_name(team_name, provider, integration),
                "description": self._make_client_description(
                    team_name, provider, integration
                ),
                "scopes": scopes,
                "token_endpoint_auth_method": "private_key_jwt",
                "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
                "integration_type": "maskinporten",
                "application_type": "web",
            },
        )

    def create_idporten_client(
        self,
        team_name,
        provider,
        integration,
        client_uri,
        redirect_uris,
        post_logout_redirect_uris,
        frontchannel_logout_uri=None,
    ):
        return self._request(
            "POST",
            ["idporten:dcr.write"],
            json={
                "application_type": "web",
                "client_name": self._make_client_name(team_name, provider, integration),
                "client_uri": str(client_uri),
                "description": self._make_client_description(
                    team_name, provider, integration
                ),
                "code_challenge_method": "S256",
                "frontchannel_logout_session_required": True,
                "frontchannel_logout_uri": str(frontchannel_logout_uri),
                "grant_types": ["authorization_code", "refresh_token"],
                "integration_type": "idporten",
                "post_logout_redirect_uris": [
                    str(u) for u in post_logout_redirect_uris
                ],
                "redirect_uris": [str(u) for u in redirect_uris],
                "refresh_token_usage": "ONETIME",
                "scopes": ["openid", "profile"],
                "sso_disabled": False,
                "token_endpoint_auth_method": "private_key_jwt",
            },
        )

    def get_client(self, client_id: str):
        return self._request("GET", ["idporten:dcr.read"], f"/{client_id}")

    def get_clients(self):
        return self._request("GET", ["idporten:dcr.read"])

    def delete_client(self, client_id: str):
        return self._request("DELETE", ["idporten:dcr.write"], f"/{client_id}")

    def create_client_key(self, client_id: str, jwk: dict):
        existing_jwks = self.get_client_keys(client_id).json().get("keys", [])

        if len(existing_jwks) >= self.MAX_KEYS:
            raise TooManyKeysError(client_id, self.MAX_KEYS)

        return self._request(
            "POST",
            ["idporten:dcr.write"],
            f"/{client_id}/jwks",
            # We need to send every existing key together with the new one,
            # otherwise all the existing keys are deleted.
            json={"keys": [jwk, *map(_jwk_ensure_use_sig, existing_jwks)]},
        )

    def delete_client_key(self, client_id, key_id):
        self._delete_client_key_lock.acquire()

        try:
            existing_jwks = self.get_client_keys(client_id).json().get("keys", [])
            updated_jwks = [jwk for jwk in existing_jwks if jwk["kid"] != key_id]

            if len(existing_jwks) == len(updated_jwks):
                raise KeyNotFoundError(client_id, key_id)

            if len(updated_jwks) == 0:
                # When deleting the last key, we need to DELETE instead of
                # POST-ing an empty `keys` object.
                return self._request(
                    "DELETE",
                    ["idporten:dcr.write"],
                    f"/{client_id}/jwks",
                )

            return self._request(
                "POST",
                ["idporten:dcr.write"],
                f"/{client_id}/jwks",
                json={"keys": updated_jwks},
            )
        finally:
            self._delete_client_key_lock.release()

    def get_client_keys(self, client_id: str):
        return self._request(
            "GET",
            ["idporten:dcr.read"],
            f"/{client_id}/jwks",
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
