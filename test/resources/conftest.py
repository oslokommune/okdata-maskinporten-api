import boto3
import pytest
from keycloak import KeycloakOpenID
from moto import mock_dynamodb2
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
def maskinporten_get_client_response(maskinporten_create_client_response):
    """Currently the same response as when creating a new client."""
    return maskinporten_create_client_response


@pytest.fixture
def maskinporten_get_clients_response(maskinporten_get_client_response):
    return [maskinporten_get_client_response]


@pytest.fixture
def maskinporten_create_client_key_response():
    return {
        "keys": [
            {
                "kid": "1970-01-01-12-00-00",
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
def maskinporten_list_client_keys_response(maskinporten_create_client_key_response):
    """Currently the same response as when creating a new key."""
    return maskinporten_create_client_key_response


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

    def token(self, grant_type):
        return {
            "token_type": "Bearer",
            "access_token": valid_token,
        }

    monkeypatch.setattr(KeycloakOpenID, "token", token)


@pytest.fixture
@mock_dynamodb2
def mock_dynamodb():
    dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
    dynamodb.create_table(
        TableName="maskinporten-audit-trail",
        KeySchema=[
            {"AttributeName": "Id", "KeyType": "HASH"},
            {"AttributeName": "Type", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "Id", "AttributeType": "S"},
            {"AttributeName": "Type", "AttributeType": "S"},
        ],
        ProvisionedThroughput={
            "ReadCapacityUnits": 5,
            "WriteCapacityUnits": 5,
        },
    )
    return dynamodb
