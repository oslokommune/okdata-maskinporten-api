import base64

import requests
from OpenSSL import crypto

from maskinporten_api.jwt_client import JWTAuthClient, JWTConfig
from maskinporten_api.ssm import get_secret
from maskinporten_api.util import getenv
from models import MaskinportenClientIn

IDPORTEN_OIDC_WELLKNOWN = {
    "test": "https://oidc-ver2.difi.no/idporten-oidc-provider/.well-known/openid-configuration",
    "prod": "https://oidc.difi.no/idporten-oidc-provider/.well-known/openid-configuration",
}

MASKINPORTEN_CLIENTS_ENDPOINTS = {
    "test": "https://integrasjon-ver2.difi.no/clients/",
    "prod": "https://integrasjon.difi.no/clients/",
}


class MaskinportenClient:
    def __init__(self, env):
        p12_encoded = get_secret(f"/dataplatform/maskinporten/origo-certificate-{env}")
        password = get_secret(
            f"/dataplatform/maskinporten/origo-certificate-password-{env}"
        )
        p12 = crypto.load_pkcs12(
            base64.b64decode(p12_encoded), password.encode("utf-8")
        )
        conf = JWTConfig(
            issuer=getenv("MASKINPORTEN_ADMIN_CLIENT_ID"),
            certificate=p12.get_certificate(),
            private_key=p12.get_privatekey(),
        )
        self.client = JWTAuthClient(conf, IDPORTEN_OIDC_WELLKNOWN[env])
        self.base_url = MASKINPORTEN_CLIENTS_ENDPOINTS[env]

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
