"""Module for obtaining access tokens for Maskinporten.

The main entry point is the `JWTAuthClient.get_access_token` method. Example
usage:

    conf = JWTConfig(
        issuer=my_issuer,
        consumer_org=my_consumer_org,
        certificate=my_certificate,
        private_key=my_private_key,
    )
    client = JWTAuthClient(conf, my_well_known_endpoint)
    access_token = client.get_access_token(["list", "of", "scopes"])
"""

import base64
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt
import requests

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from pydantic import BaseModel


class JWTAuthError(Exception):
    def __init__(self, status_code, error_description):
        super().__init__(
            f"Got status code {status_code} from Maskinporten: {error_description}"
        )


@dataclass
class JWTConfig:
    issuer: str
    certificate: x509.Certificate
    private_key: rsa.RSAPrivateKey
    consumer_org: str = None


class JWTGenerator:
    jwt_config: JWTConfig

    def __init__(self, jwt_config):
        self.jwt_config = jwt_config

    def _jws_headers(self):
        """Return JWT headers for the present certificate."""
        x5c = base64.b64encode(
            # Serialize the certificate to the underlying ASN.1 data structure
            # using it's main serialization format "Distinguished Encoding Rules" (DER).
            # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.public_bytes
            self.jwt_config.certificate.public_bytes(Encoding.DER),
        )
        return {
            "x5c": [x5c.decode("utf-8")],
            "alg": "RS256",
        }

    def _claims(self, audience, scopes):
        """Return a JWT payload (a set of claims) for `audience` and `scopes`.

        The expiration time is currently hard-coded to 120 seconds. Both issue
        time (iat) and expiration time (exp) are given as POSIX timestamps.
        """
        now = datetime.now()
        expiration_time = now + timedelta(seconds=120)

        claims = {
            "aud": audience,
            "exp": int(expiration_time.timestamp()),
            "iat": int(now.timestamp()),
            "iss": self.jwt_config.issuer,
            "jti": str(uuid.uuid4()),  # Must be unique for each grant.
            "scope": " ".join(scopes),
        }

        if self.jwt_config.consumer_org:
            claims["consumer_org"] = self.jwt_config.consumer_org

        return claims

    def generate_jwt(self, audience, scopes):
        """Return a freshly generated JWT for `audience` and `scopes`."""
        headers = self._jws_headers()
        claims = self._claims(audience, scopes)
        pk = self.jwt_config.private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )

        return jwt.encode(claims, pk, algorithm="RS256", headers=headers)


class AccessToken(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    scope: str

    def __str__(self):
        return self.access_token


class JWTAuthClient:
    def __init__(self, jwt_config, well_known_endpoint):
        self.jwt_config = jwt_config
        self.jwt_generator = JWTGenerator(jwt_config)

        well_known_conf = json.loads(requests.get(well_known_endpoint).text)
        self.audience = well_known_conf["issuer"]
        self.token_endpoint = well_known_conf["token_endpoint"]
        logging.debug("Maskinporten auth client:")
        logging.debug(f"  Audience: {self.audience}")
        logging.debug(f"  Endpoint: {self.token_endpoint}")

    def get_access_token(self, scopes):
        jwt = self.jwt_generator.generate_jwt(self.audience, scopes)

        response = requests.post(
            self.token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jwt,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "*/*",
            },
        )
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            raise JWTAuthError(response.status_code, response.text)

        token = AccessToken.parse_obj(response.json())

        logging.debug(
            f"Received Maskinporten token valid for {token.expires_in} seconds"
        )
        return token
