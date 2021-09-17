import pytest

from keycloak import KeycloakOpenID
from okdata.resource_auth import ResourceAuthorizer


valid_token = "valid-token"
valid_token_no_access = "valid-token-no-access"
username = "janedoe"


@pytest.fixture
def maskinporten_create_client_response():
    return {
        "client_name": "some-client",
        "description": "Very cool client",
        "scopes": ["folkeregister:deling/offentligmedhjemmel"],
        "authorization_lifetime": 0,
        "access_token_lifetime": 0,
        "refresh_token_lifetime": 0,
        "refresh_token_usage": "ONETIME",
        "frontchannel_logout_session_required": False,
        "token_endpoint_auth_method": "private_key_jwt",
        "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
        "integration_type": "maskinporten",
        "application_type": "web",
        "last_updated": "2021-09-15T10:20:43.354+02:00",
        "created": "2021-09-15T10:20:43.354+02:00",
        "client_id": "d1427568-1eba-1bf2-59ed-1c4af065f30e",
        "client_orgno": "123456789",
        "active": True,
    }


@pytest.fixture
def maskinporten_list_client_keys_response():
    return {
        "keys": [
            {
                "kid": "some-client-ab0f2066-feb8-8bdc-7bbc-24994da79391",
                "alg": "RS256",
                "n": "nYFc81LY5FoxWcKh",
                "e": "AQAB",
                "kty": "RSA",
                "exp": 1663324457,
            }
        ],
        "last_updated": "2021-09-16T12:34:17.099+02:00",
        "created": "2021-09-16T12:34:17.099+02:00",
    }


@pytest.fixture
def mock_authorizer(monkeypatch):
    def has_access(self, bearer_token, scope, resource_name=None, use_whitelist=False):
        return bearer_token == valid_token and scope in [
            "okdata:maskinporten-client:create"
        ]

    monkeypatch.setattr(ResourceAuthorizer, "has_access", has_access)

    def introspect(self, token):
        return {
            "active": token in [valid_token, valid_token_no_access],
            "username": username,
        }

    monkeypatch.setattr(KeycloakOpenID, "introspect", introspect)
