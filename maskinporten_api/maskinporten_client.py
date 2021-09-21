import base64
import os

import requests
from OpenSSL import crypto

from maskinporten_api.jwt_client import JWTAuthClient, JWTConfig
from maskinporten_api.ssm import get_secret
from models import MaskinportenClientIn


class MaskinportenClient:
    def __init__(self, env):
        p12_encoded = get_secret(f"/dataplatform/maskinporten/origo-certificate-{env}")
        p12 = crypto.load_pkcs12(
            base64.b64decode(p12_encoded), os.getenv("MASKINPORTEN_KEY_PASSWORD")
        )
        conf = JWTConfig(
            issuer=os.getenv("MASKINPORTEN_ADMIN_CLIENT_ID"),
            certificate=p12.get_certificate(),
            private_key=p12.get_privatekey(),
        )
        self.client = JWTAuthClient(conf, os.getenv("IDPORTEN_OIDC_WELLKNOWN"))
        self.base_url = os.getenv("MASKINPORTEN_CLIENTS_ENDPOINT")

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
