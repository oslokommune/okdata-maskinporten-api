import os
import base64
import secrets
import string
from datetime import datetime
from zoneinfo import ZoneInfo

from OpenSSL import crypto
from authlib.jose import jwk


def generate_key() -> crypto.PKey:
    """Return a freshly made 4096 bit RSA key pair."""
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)
    return key


def jwk_from_key(key: crypto.PKey):
    """Return a JSON Web Key (JWK) payload representing `key`."""
    return {
        "kid": datetime.now(tz=ZoneInfo(key=os.environ["TIMEZONE"])).strftime(
            "kid-%Y-%m-%d-%H-%M-%S"
        ),
        "alg": "RS256",
        **jwk.dumps(crypto.dump_publickey(crypto.FILETYPE_PEM, key)),
    }


def pkcs12_from_key(key: crypto.PKey, key_alias: str, passphrase: str) -> str:
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


def generate_password(pw_length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for i in range(pw_length))
