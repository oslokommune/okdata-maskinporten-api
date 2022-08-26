import os
import base64
import secrets
import string
from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from OpenSSL import crypto
from authlib.jose import jwk

from maskinporten_api.util import getenv


@dataclass
class Key:
    jwk: dict
    keystore: str
    alias: str
    password: str


def _generate_key() -> crypto.PKey:
    """Return a freshly made 4096 bit RSA key pair."""
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)
    return key


def _jwk_from_key(key: crypto.PKey, expiration_days):
    """Return a JSON Web Key (JWK) payload representing `key`.

    The key expires in `expiration_days` days.
    """
    now = datetime.now(tz=ZoneInfo(key=os.environ["TIMEZONE"]))
    expiry = now + timedelta(days=expiration_days)

    return {
        "kid": now.strftime("kid-%Y-%m-%d-%H-%M-%S"),
        "alg": "RS256",
        **jwk.dumps(crypto.dump_publickey(crypto.FILETYPE_PEM, key)),
        "exp": int(expiry.timestamp()),
    }


def _pkcs12_from_key(key: crypto.PKey, key_alias: str, passphrase: str) -> str:
    """Return a Base64-encoded PKCS #12 archive containing `key`.

    `key_alias` is the alias/friendly name of the key in the keystore.

    `passphrase` is used to encrypt the structure.
    """
    pkcs12 = crypto.PKCS12()
    pkcs12.set_privatekey(key)
    pkcs12.set_friendlyname(key_alias.encode("utf-8"))
    return base64.b64encode(
        pkcs12.export(passphrase.encode("utf-8")),
    ).decode("utf-8")


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
