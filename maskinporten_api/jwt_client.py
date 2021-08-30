import base64
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt
from OpenSSL import crypto


@dataclass
class JWTConfig:
    issuer: str
    consumer_org: str
    certificate: crypto.X509
    private_key: crypto.PKey


class JWTGenerator:
    def __init__(self, jwt_config):
        self.jwt_config = jwt_config

    def _jws_headers(self):
        """Return JWT headers for the present certificate."""
        x5c = base64.b64encode(
            crypto.dump_certificate(crypto.FILETYPE_ASN1, self.jwt_config.certificate)
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

        return {
            "aud": audience,
            "exp": int(expiration_time.timestamp()),
            "iat": int(now.timestamp()),
            "iss": self.jwt_config.issuer,
            "jti": str(uuid.uuid4()),  # Must be unique for each grant.
            "scope": " ".join(scopes),
        }

    def generate_jwt(self, audience, scopes):
        """Return a freshly generated JWT for `audience` and `scopes`."""
        headers = self._jws_headers()
        claims = self._claims(audience, scopes)
        pk = crypto.dump_privatekey(crypto.FILETYPE_PEM, self.jwt_config.private_key)

        return jwt.encode(claims, pk, algorithm="RS256", headers=headers)
