import os

import boto3
import moto
import requests_mock

from test.mock_utils import mock_access_token_generation_requests


@moto.mock_ssm
def test_create_client(mock_client, maskinporten_create_client_response):
    ssm = boto3.client("ssm", region_name=os.environ["AWS_REGION"])
    with open("test/data/test.p12.txt") as f:
        ssm.put_parameter(
            Name="/dataplatform/maskinporten/origo-certificate-test",
            Value=f.read(),
            Type="SecureString",
        )

    body = {
        "name": "some-client",
        "description": "Very cool client",
        "scopes": ["folkeregister:deling/offentligmedhjemmel"],
        "env": "test",
    }
    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.post(
            "https://example.org/clients/",
            json=maskinporten_create_client_response,
        )
        response = mock_client.post("/clients", json=body)

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
