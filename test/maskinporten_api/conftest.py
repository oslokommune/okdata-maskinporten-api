import pytest
from OpenSSL import crypto

from maskinporten_api.jwt_client import JWTConfig, JWTGenerator


@pytest.fixture
def jwt_config():
    with open("test/data/test.p12", "rb") as f:
        p12 = crypto.load_pkcs12(f.read(), b"test")
    return JWTConfig(
        issuer="foo-corp",
        consumer_org="123",
        certificate=p12.get_certificate(),
        private_key=p12.get_privatekey(),
    )


@pytest.fixture
def jwt_generator(jwt_config):
    return JWTGenerator(jwt_config)
