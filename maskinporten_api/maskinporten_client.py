import base64
import os

import requests
from OpenSSL import crypto

from maskinporten_api.jwt_client import JWTAuthClient, JWTConfig
from maskinporten_api.ssm import get_secret


class MaskinportenClient:
    def __init__(self, env="test"):
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

    def request(self, method, scopes, path="", json=None):
        base_url = os.getenv("MASKINPORTEN_CLIENTS_ENDPOINT")
        access_token = self.client.get_access_token(scopes)

        response = requests.request(
            method,
            f"{base_url}{path}",
            headers={
                "Accept": "*/*",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
            json=json,
        )
        response.raise_for_status()

        return response
