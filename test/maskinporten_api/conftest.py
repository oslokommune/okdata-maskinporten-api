import pytest

from cryptography.hazmat.primitives.serialization import pkcs12

from maskinporten_api.jwt_client import JWTConfig, JWTGenerator
from maskinporten_api.maskinporten_client import MaskinportenClient


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


@pytest.fixture
def maskinporten_client(mock_ssm):
    return MaskinportenClient("test")


@pytest.fixture
def client_error_response():
    return {
        "status": 400,
        "timestamp": "2025-07-02T08:30:00.000000000Z",
        "correlation_id": "b496e785cbd430eee802c1eaafa76f46",
        "errors": [
            {
                "errorMessage": "error 1",
                "isFieldError": True,
                "objectName": "Client",
                "fieldIdentifier": "field_1",
            },
            {
                "errorMessage": "error 2",
                "isFieldError": True,
                "objectName": "Client",
                "fieldIdentifier": "field_2",
            },
        ],
        "error": ", error 1, error 2",
        "error_description": ", error 1, error 2",
    }
