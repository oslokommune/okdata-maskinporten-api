import os

import requests_mock

from test.mock_utils import mock_access_token_generation_requests
from test.resources.conftest import valid_token


def test_create_client(
    mock_client, mock_aws, mock_authorizer, maskinporten_create_client_response
):
    body = {
        "name": "some-client",
        "description": "Very cool client",
        "scopes": ["folkeregister:deling/offentligmedhjemmel"],
        "env": "test",
    }
    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.post(
            os.getenv("MASKINPORTEN_CLIENTS_ENDPOINT"),
            json=maskinporten_create_client_response,
        )
        response = mock_client.post(
            "/clients", json=body, headers={"Authorization": f"Bearer {valid_token}"}
        )

    assert response.json() == {
        "client_id": "d1427568-1eba-1bf2-59ed-1c4af065f30e",
        "name": "some-client",
        "description": "Very cool client",
        "scopes": ["folkeregister:deling/offentligmedhjemmel"],
        "active": True,
    }


def test_create_client_key(mock_client):
    client_id = "some-client-id"

    assert mock_client.post(f"/clients/{client_id}/keys").json() == {
        "key_id": f"{client_id}-uuid",
        "key": "some-key",
    }


def test_list_client_keys(mock_client):
    client_id = "some-client-id"

    assert mock_client.get(f"/clients/{client_id}/keys").json() == [
        {
            "key_id": f"{client_id}-uuid",
            "client_id": client_id,
        }
    ]
