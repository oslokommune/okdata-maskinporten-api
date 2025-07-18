import pytest
from keycloak import KeycloakOpenID
from okdata.resource_auth import ResourceAuthorizer
from pydantic import BaseModel


class MockUser(BaseModel):
    principal_id: str
    access_token: str
    permissions: list[str] = []

    @property
    def bearer_token(self):
        return f"Bearer {self.access_token}"

    @property
    def permissions_api_my_permissions_response(self):
        resource_permissions = {}
        for permission in self.permissions:
            permission_resource, permission_scope = permission.split("#")
            if permission_resource:
                resource_permissions.setdefault(permission_resource, {"scopes": []})
                resource_permissions[permission_resource]["scopes"].append(
                    permission_scope
                )
        return resource_permissions


valid_client_token = "valid-token"
team_id = "2cac0456-372f-d20a-054e-f9df155bb2f9"

mock_user_pool = [
    MockUser(
        principal_id="janedoe",
        access_token="abc-123",
        permissions=[
            "#maskinporten:client:create",
            "maskinporten:client:test-d1427568-1eba-1bf2-59ed-1c4af065f30e#maskinporten:client:read",
            "maskinporten:client:test-d1427568-1eba-1bf2-59ed-1c4af065f30e#maskinporten:client:write",
        ],
    ),
    MockUser(
        principal_id="homersimpson",
        access_token="def-456",
        permissions=[
            "maskinporten:client:some-client#maskinporten:client:read",
            "maskinporten:client:some-client#maskinporten:client:write",
        ],
    ),
    MockUser(principal_id="nibbler", access_token="bdf-246"),
]


def get_mock_user(principal_id):
    for user in mock_user_pool:
        if user.principal_id == principal_id:
            return user
    return None


def maskinporten_client_response(
    client_id,
    client_name,
    scopes=["folkeregister:deling/offentligmedhjemmel"],
):
    return {
        "client_name": client_name,
        "description": "Freg-klient for testing (My team)",
        "scopes": scopes,
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
        "client_id": client_id,
        "client_orgno": "123456789",
        "active": True,
    }


def idporten_client_response(client_id, client_name):
    return {
        "client_name": client_name,
        "client_uri": "http://localhost:8000",
        "description": "Test client",
        "scopes": ["openid", "profile"],
        "redirect_uris": ["http://localhost:8000/auth/callback"],
        "post_logout_redirect_uris": ["http://localhost:8000/"],
        "authorization_lifetime": 0,
        "access_token_lifetime": 0,
        "refresh_token_lifetime": 0,
        "refresh_token_usage": "ONETIME",
        "frontchannel_logout_uri": "http://localhost:8000/auth/logout",
        "frontchannel_logout_session_required": True,
        "token_endpoint_auth_method": "private_key_jwt",
        "grant_types": ["authorization_code", "refresh_token"],
        "integration_type": "idporten",
        "application_type": "web",
        "sso_disabled": False,
        "code_challenge_method": "S256",
        "last_updated": "2024-01-01T20:00:00.000Z",
        "created": "2024-01-01T20:00:00.000Z",
        "client_id": client_id,
        "client_orgno": "123456789",
        "active": True,
        "jwks_uri": f"/clients/{client_id}/jwks",
    }


@pytest.fixture
def maskinporten_create_client_body():
    return {
        "client_type": "maskinporten",
        "team_id": team_id,
        "provider": "freg",
        "integration": "testing",
        "scopes": ["folkeregister:deling/offentligmedhjemmel"],
        "env": "test",
    }


@pytest.fixture
def idporten_create_client_body():
    return {
        "client_type": "idporten",
        "team_id": team_id,
        "provider": "idporten",
        "integration": "testing",
        "env": "test",
        "client_uri": "http://localhost",
        "frontchannel_logout_uri": "http://localhost",
        "redirect_uris": ["http://localhost"],
        "post_logout_redirect_uris": ["http://localhost"],
    }


@pytest.fixture
def maskinporten_create_client_response():
    return maskinporten_client_response(
        client_id="d1427568-1eba-1bf2-59ed-1c4af065f30e",
        client_name="my-team-freg-testing",
    )


@pytest.fixture
def idporten_create_client_response():
    return idporten_client_response(
        client_id="1a7a504d-bb4c-239d-1469-61e220c3bcb6",
        client_name="my-team-idporten-testing",
    )


@pytest.fixture
def maskinporten_get_client_response(maskinporten_create_client_response):
    """Currently the same response as when creating a new client."""
    return maskinporten_create_client_response


@pytest.fixture
def maskinporten_get_clients_response(maskinporten_get_client_response):
    return [
        maskinporten_get_client_response,
        maskinporten_client_response(
            client_id="a70c6d97-51c2-4a08-83ce-50f44ebf8921",
            client_name="another-client",
        ),
    ]


@pytest.fixture
def maskinporten_create_client_key_response():
    return {
        "keys": [
            {
                "kid": "kid-1970-01-01-01-00-00",
                "alg": "RS256",
                "use": "sig",
                "n": "nYFc81LY5FoxWcKh",
                "e": "AQAB",
                "kty": "RSA",
                "exp": 1577836800,
            }
        ],
        "last_updated": "2021-09-16T12:34:17.099+02:00",
        "created": "2021-09-16T12:34:17.099+02:00",
    }


@pytest.fixture
def maskinporten_delete_client_key_response(maskinporten_create_client_key_response):
    """Currently the same response as when creating a new key."""
    return maskinporten_create_client_key_response


@pytest.fixture
def maskinporten_list_client_keys_response(maskinporten_create_client_key_response):
    """Currently the same response as when creating a new key."""
    return maskinporten_create_client_key_response


@pytest.fixture
def user_team_response():
    return {"id": team_id, "name": "foobar", "is_member": True}


@pytest.fixture
def mock_authorizer(monkeypatch):
    def has_access(self, bearer_token, scope, resource_name=None, use_whitelist=False):
        for user in mock_user_pool:
            if user.access_token != bearer_token:
                continue

            target_permission = f"{resource_name or ''}#{scope}"

            for permission in user.permissions:
                if permission == target_permission:
                    return True

                permission_resource, permission_scope = permission.split("#")

                if scope != permission_scope:
                    continue

                if not resource_name or resource_name == permission_resource:
                    return True
        return False

    monkeypatch.setattr(ResourceAuthorizer, "has_access", has_access)

    def introspect(self, token):
        for user in mock_user_pool:
            if token == user.access_token:
                return {
                    "active": True,
                    "username": user.principal_id,
                }
        return {"active": False, "username": "ash"}

    monkeypatch.setattr(KeycloakOpenID, "introspect", introspect)

    def token(self, grant_type):
        return {
            "token_type": "Bearer",
            "access_token": valid_client_token,
        }

    monkeypatch.setattr(KeycloakOpenID, "token", token)
