import os

import pytest
import requests_mock
from unittest.mock import ANY

from resources import maskinporten_clients
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


def test_create_client_key(
    mock_client,
    mock_aws,
    mock_authorizer,
    maskinporten_get_client_response,
    maskinporten_create_client_key_response,
    mocker,
):
    mocker.spy(maskinporten_clients.SendSecretsService, "send_secrets")

    client_id = "some-client"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.get(
            f"{os.getenv('MASKINPORTEN_CLIENTS_ENDPOINT')}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.post(
            f"{os.getenv('MASKINPORTEN_CLIENTS_ENDPOINT')}{client_id}/jwks",
            json=maskinporten_create_client_key_response,
        )

        destination_aws_account = "123456789876"
        destination_aws_region = "eu-west-1"
        response = mock_client.post(
            f"/clients/test/{client_id}/keys",
            json={
                "destination_aws_account": destination_aws_account,
                "destination_aws_region": destination_aws_region,
            },
            headers={
                "Authorization": f"Bearer {valid_token}",
            },
        )

    maskinporten_clients.SendSecretsService.send_secrets.assert_called_once_with(
        ANY,
        secrets=maskinporten_clients.Secrets(ANY, ANY, ANY),
        maskinporten_client_id=client_id,
        destination_aws_account_id=destination_aws_account,
        destination_aws_region=destination_aws_region,
    )
    assert response.json() == {
        "kid": "some-client-ab0f2066-feb8-8bdc-7bbc-24994da79391",
    }


def test_create_client_key_assume_role_access_denied(
    mock_client,
    mock_aws,
    mock_authorizer,
    raise_assume_role_access_denied,
    maskinporten_get_client_response,
    maskinporten_create_client_key_response,
    mocker,
):
    mocker.spy(maskinporten_clients.SendSecretsService, "send_secrets")

    client_id = "some-client"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.get(
            f"{os.getenv('MASKINPORTEN_CLIENTS_ENDPOINT')}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.post(
            f"{os.getenv('MASKINPORTEN_CLIENTS_ENDPOINT')}{client_id}/jwks",
            json=maskinporten_create_client_key_response,
        )

        destination_aws_account = "123456789876"
        destination_aws_region = "eu-west-1"

        response = mock_client.post(
            f"/clients/test/{client_id}/keys",
            json={
                "destination_aws_account": destination_aws_account,
                "destination_aws_region": destination_aws_region,
            },
            headers={
                "Authorization": f"Bearer {valid_token}",
            },
        )

    assert response.status_code == 422
    assert response.json() == {
        "message": "Error message from aws",
    }


def test_list_client_keys(
    mock_client, mock_authorizer, maskinporten_list_client_keys_response
):
    client_id = "some-client"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.get(
            f"{os.getenv('MASKINPORTEN_CLIENTS_ENDPOINT')}{client_id}/jwks",
            json=maskinporten_list_client_keys_response,
        )
        response = mock_client.get(
            f"/clients/test/{client_id}/keys",
            headers={"Authorization": f"Bearer {valid_token}"},
        )

    assert response.json() == [
        {
            "kid": "some-client-ab0f2066-feb8-8bdc-7bbc-24994da79391",
            "client_id": client_id,
        }
    ]


@pytest.fixture
def raise_assume_role_access_denied(monkeypatch):
    def send_secrets(
        self,
        secrets,
        maskinporten_client_id,
        destination_aws_account_id,
        destination_aws_region,
    ):
        raise maskinporten_clients.AssumeRoleAccessDeniedException(
            "Error message from aws"
        )

    monkeypatch.setattr(
        maskinporten_clients.SendSecretsService, "send_secrets", send_secrets
    )
