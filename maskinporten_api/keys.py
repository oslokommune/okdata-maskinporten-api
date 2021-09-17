import uuid

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
