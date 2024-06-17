from datetime import datetime

from freezegun import freeze_time

from maskinporten_api.keys import _generate_key, _jwk_from_key


@freeze_time("1970-01-01")
def test_jwk_from_key():
    key = _generate_key()
    jwk = _jwk_from_key(key, 3)

    assert jwk["kid"] == "kid-1970-01-01-01-00-00"
    assert jwk["alg"] == "RS256"
    assert isinstance(jwk["n"], str)
    assert isinstance(jwk["e"], str)
    assert jwk["kty"] == "RSA"
    assert jwk["exp"] == int(datetime(1970, 1, 4).timestamp())
