import os

import requests_mock
from unittest.mock import ANY

from maskinporten_api.ssm import SSMService, Secrets
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
    mocker.spy(SSMService, "send_secrets")

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
            data={
                "destination_aws_account": destination_aws_account,
                "destination_aws_region": destination_aws_region,
            },
            headers={
                "Authorization": f"Bearer {valid_token}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

    SSMService.send_secrets.assert_called_once_with(
        ANY,
        secrets=Secrets(ANY, ANY, ANY),
        maskinporten_client_id=client_id,
        destination_aws_account_id=destination_aws_account,
        destination_aws_region=destination_aws_region,
    )
    assert response.json() == {
        "kid": "some-client-ab0f2066-feb8-8bdc-7bbc-24994da79391",
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
