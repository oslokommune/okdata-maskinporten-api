import os
import base64
import secrets
import string
from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from authlib.jose import jwk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PublicFormat,
    pkcs12,
)

from maskinporten_api.util import getenv


@dataclass
class Key:
    jwk: dict
    keystore: str
    alias: str
    password: str


def _generate_key() -> rsa.RSAPrivateKey:
    """Return a freshly made 4096 bit RSA key pair."""
    key = rsa.generate_private_key(
        # Indicates what one mathematical property of the key generation will
        # be. Should be `65537` unless specific reason to do otherwise. See
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        public_exponent=65537,
        key_size=4096,
    )
    return key


def _jwk_from_key(key: rsa.RSAPrivateKey, expiration_days):
    """Return a JSON Web Key (JWK) payload representing `key`.

    The key expires in `expiration_days` days.
    """
    now = datetime.now(tz=ZoneInfo(key=os.environ["TIMEZONE"]))
    expiry = now + timedelta(days=expiration_days)

    public_key = key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "kid": now.strftime("kid-%Y-%m-%d-%H-%M-%S"),
        "alg": "RS256",
        **jwk.dumps(public_key),
        "exp": int(expiry.timestamp()),
    }


def _pkcs12_from_key(
    key: rsa.RSAPrivateKey,
    key_alias: str,
    passphrase: str,
) -> str:
    """Return a Base64-encoded PKCS #12 archive containing `key`.

    `key_alias` is the alias/friendly name of the key in the keystore.

    `passphrase` is used to encrypt the structure.
    """
    serialized_pkcs12 = pkcs12.serialize_key_and_certificates(
        name=key_alias.encode("utf-8"),
        key=key,
        cert=None,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    return base64.b64encode(serialized_pkcs12).decode("utf-8")


def _generate_password(pw_length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for i in range(pw_length))


def create_key(expiration_days) -> Key:
    """Return a freshly generated `Key`.

    The key expires in `expiration_days` days.
    """
    key = _generate_key()
    alias = getenv("MASKINPORTEN_KEY_ALIAS")
    password = _generate_password(pw_length=32)

    return Key(
        jwk=_jwk_from_key(key, expiration_days),
        keystore=_pkcs12_from_key(key, alias, password),
        alias=alias,
        password=password,
    )
