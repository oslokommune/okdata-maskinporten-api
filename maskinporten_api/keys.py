import base64
import uuid
import secrets
import string

from OpenSSL import crypto
from authlib.jose import jwk


def generate_key():
    """Return a freshly made 4096 bit RSA key pair."""
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)
    return key


def jwk_from_key(key, client_name):
    """Return a JSON Web Key (JWK) payload representing `key`.

    `client_name` is baked into the key ID together with a UUID.
    """
    return {
        "kid": f"{client_name}-{uuid.uuid4()}",
        "alg": "RS256",
        **jwk.dumps(crypto.dump_publickey(crypto.FILETYPE_PEM, key)),
    }


def pkcs12_from_key(key, passphrase):
    """Return a Base64-encoded PKCS #12 archive containing `key`.

    `passphrase` is used to encrypt the structure.
    """
    pkcs12 = crypto.PKCS12()
    pkcs12.set_privatekey(key)
    return base64.b64encode(pkcs12.export(passphrase)).decode("utf-8")


def generate_password(pw_length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for i in range(pw_length))
