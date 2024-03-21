import pytest

from cryptography.hazmat.primitives.serialization import pkcs12

from maskinporten_api.jwt_client import JWTConfig, JWTGenerator


@pytest.fixture
def jwt_config():
    with open("test/data/test.p12", "rb") as f:
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            f.read(),
            b"test",
        )
    return JWTConfig(
        issuer="foo-corp",
        consumer_org="123",
        certificate=certificate,
        private_key=private_key,
    )


@pytest.fixture
def jwt_generator(jwt_config):
    return JWTGenerator(jwt_config)
