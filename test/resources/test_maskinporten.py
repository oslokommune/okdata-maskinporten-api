import os
from unittest.mock import patch

import pytest
import requests_mock

from freezegun import freeze_time
from maskinporten_api.maskinporten_client import env_config
from maskinporten_api.audit import _slack_message_payload
from resources import maskinporten
from test.mock_utils import mock_access_token_generation_requests
from test.resources.conftest import get_mock_user, valid_client_token, team_id

CLIENTS_ENDPOINT = env_config("test").maskinporten_clients_endpoint
OKDATA_PERMISSION_API_URL = os.environ["OKDATA_PERMISSION_API_URL"]
SLACK_WEBHOOK_URL = os.environ["SLACK_MASKINPORTEN_API_ALERTS_WEBHOOK_URL"]


def test_create_client(
    maskinporten_create_client_body,
    maskinporten_create_client_response,
    user_team_response,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    with requests_mock.Mocker(real_http=True) as rm:
        mock_user = get_mock_user("janedoe")
        mock_access_token_generation_requests(rm)

        rm.post(
            CLIENTS_ENDPOINT,
            json=maskinporten_create_client_response,
        )

        teams_api_matcher = rm.get(
            f"{OKDATA_PERMISSION_API_URL}/teams/{team_id}",
            json=user_team_response,
        )
        permissions_api_matcher = rm.post(
            f"{OKDATA_PERMISSION_API_URL}/permissions",
        )
        audit_notify_matcher = rm.post(SLACK_WEBHOOK_URL)

        created_client = mock_client.post(
            "/clients",
            json=maskinporten_create_client_body,
            headers={"Authorization": mock_user.bearer_token},
        ).json()

    client = {
        "client_id": "d1427568-1eba-1bf2-59ed-1c4af065f30e",
        "client_name": "my-team-freg-testing",
        "description": "Freg-klient for testing (My team)",
        "scopes": ["folkeregister:deling/offentligmedhjemmel"],
        "created": "2021-09-15T10:20:43.354000+02:00",
        "last_updated": "2021-09-15T10:20:43.354000+02:00",
        "active": True,
    }
    assert created_client == client

    teams_request = teams_api_matcher.last_request
    assert teams_request.headers["Authorization"] == f"Bearer {mock_user.access_token}"

    permissions_request = permissions_api_matcher.last_request
    assert (
        permissions_request.headers["Authorization"] == f"Bearer {valid_client_token}"
    )
    assert permissions_request.json() == {
        "owner": {
            "user_id": user_team_response["name"],
            "user_type": "team",
        },
        "resource_name": f"maskinporten:client:{maskinporten_create_client_body['env']}-{client['client_id']}",
    }

    table = mock_dynamodb.Table("maskinporten-audit-trail")
    audit_log_entry = table.get_item(Key={"Id": client["client_id"], "Type": "client"})
    assert audit_log_entry["Item"]["Id"] == client["client_id"]
    assert audit_log_entry["Item"]["Action"] == "create"

    assert audit_notify_matcher.last_request.json() == _slack_message_payload(
        "Client created",
        client["client_name"],
        maskinporten_create_client_body["env"],
        client["scopes"],
    )


def test_create_client_rollback(
    maskinporten_create_client_body,
    maskinporten_create_client_response,
    user_team_response,
    mock_authorizer,
    mock_client,
    mocker,
):
    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        create_client_matcher = rm.post(
            CLIENTS_ENDPOINT,
            json=maskinporten_create_client_response,
        )
        rm.get(
            f"{OKDATA_PERMISSION_API_URL}/teams/{team_id}",
            json=user_team_response,
        )
        rm.post(f"{OKDATA_PERMISSION_API_URL}/permissions", status_code=403)
        delete_client_matcher = rm.delete(
            f"{CLIENTS_ENDPOINT}{maskinporten_create_client_response['client_id']}"
        )
        res = mock_client.post(
            "/clients",
            json=maskinporten_create_client_body,
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert res.status_code == 500
    assert create_client_matcher.called_once
    assert delete_client_matcher.called_once


def test_create_client_no_create_permission(
    maskinporten_create_client_body,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.post(CLIENTS_ENDPOINT, json={"foo": "bar"})
        res = mock_client.post(
            "/clients",
            json=maskinporten_create_client_body,
            headers={"Authorization": get_mock_user("homersimpson").bearer_token},
        )

    assert res.status_code == 403


def test_create_client_not_team_member(
    maskinporten_create_client_body,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    with requests_mock.Mocker(real_http=True) as rm:
        mock_user = get_mock_user("janedoe")
        mock_access_token_generation_requests(rm)

        create_client_matcher = rm.post(
            CLIENTS_ENDPOINT, json=maskinporten_create_client_body
        )
        rm.get(f"{OKDATA_PERMISSION_API_URL}/teams/{team_id}", status_code=403)

        res = mock_client.post(
            "/clients",
            json=maskinporten_create_client_body,
            headers={"Authorization": mock_user.bearer_token},
        )

    assert create_client_matcher.call_count == 0
    assert res.status_code == 403


def test_create_client_team_lookup_fail(
    maskinporten_create_client_body,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    with requests_mock.Mocker(real_http=True) as rm:
        mock_user = get_mock_user("janedoe")
        mock_access_token_generation_requests(rm)

        create_client_matcher = rm.post(
            CLIENTS_ENDPOINT, json=maskinporten_create_client_body
        )
        rm.get(f"{OKDATA_PERMISSION_API_URL}/teams/{team_id}", status_code=500)

        res = mock_client.post(
            "/clients",
            json=maskinporten_create_client_body,
            headers={"Authorization": mock_user.bearer_token},
        )

    assert create_client_matcher.call_count == 0
    assert res.status_code == 500


def test_create_client_invalid_team_id(
    maskinporten_create_client_body,
    mock_authorizer,
    mock_aws,
    mock_client,
):
    body = maskinporten_create_client_body
    body["team_id"] = "invalid#-team-id-123"

    res = mock_client.post(
        "/clients",
        json=body,
        headers={"Authorization": get_mock_user("janedoe").bearer_token},
    )
    assert res.status_code == 400
    assert res.json()["message"] == "Invalid team ID (value is not a valid uuid)"


def test_list_clients(mock_client, mock_authorizer, maskinporten_get_clients_response):
    with requests_mock.Mocker(real_http=True) as rm:
        mock_user = get_mock_user("janedoe")
        mock_access_token_generation_requests(rm)
        rm.get(CLIENTS_ENDPOINT, json=maskinporten_get_clients_response)
        rm.get(
            f"{OKDATA_PERMISSION_API_URL}/my_permissions",
            json=mock_user.permissions_api_my_permissions_response,
        )
        response = mock_client.get(
            "/clients/test",
            headers={"Authorization": mock_user.bearer_token},
        )

    assert response.json() == [
        {
            "client_id": "d1427568-1eba-1bf2-59ed-1c4af065f30e",
            "client_name": "my-team-freg-testing",
            "description": "Freg-klient for testing (My team)",
            "scopes": ["folkeregister:deling/offentligmedhjemmel"],
            "created": "2021-09-15T10:20:43.354000+02:00",
            "last_updated": "2021-09-15T10:20:43.354000+02:00",
            "active": True,
        }
    ]


def test_list_clients_no_permissions(
    mock_client, mock_authorizer, maskinporten_get_clients_response
):
    with requests_mock.Mocker(real_http=True) as rm:
        mock_user = get_mock_user("homersimpson")
        mock_access_token_generation_requests(rm)
        rm.get(CLIENTS_ENDPOINT, json=maskinporten_get_clients_response)
        rm.get(
            f"{OKDATA_PERMISSION_API_URL}/my_permissions",
            json=mock_user.permissions_api_my_permissions_response,
        )
        response = mock_client.get(
            "/clients/test",
            headers={"Authorization": mock_user.bearer_token},
        )

        assert response.status_code == 200
        assert len(response.json()) == 0


def test_list_clients_unauthorized(
    mock_client, mock_authorizer, maskinporten_get_clients_response
):
    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.get(CLIENTS_ENDPOINT, json=maskinporten_get_clients_response)
        response = mock_client.get(
            "/clients/test",
            headers={"Authorization": get_mock_user("nibbler").bearer_token},
        )

        assert response.status_code == 403
        assert response.json()["message"] == "Forbidden"


def test_list_clients_validation_error(
    mock_client, mock_authorizer, maskinporten_get_clients_response
):
    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.get(CLIENTS_ENDPOINT, json=maskinporten_get_clients_response)
        response = mock_client.get(
            "/clients/hest",
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert response.status_code == 400
    assert (
        response.json()["message"]
        == "Unsupported Maskinporten environment. Must be one of: test, prod"
    )


def test_delete_client(
    maskinporten_get_client_response,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        audit_notify_matcher = rm.post(SLACK_WEBHOOK_URL)

        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.get(f"{CLIENTS_ENDPOINT}{client_id}/jwks", json={})
        rm.delete(f"{CLIENTS_ENDPOINT}{client_id}")
        res = mock_client.delete(
            f"/clients/test/{client_id}",
            json={"aws_account": None, "aws_region": None},
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert res.status_code == 200
    data = res.json()
    assert data["client_id"] == client_id
    assert data["deleted_ssm_params"] == []

    table = mock_dynamodb.Table("maskinporten-audit-trail")
    audit_log_entry = table.get_item(Key={"Id": client_id, "Type": "client"})
    assert audit_log_entry["Item"]["Action"] == "delete"
    assert audit_log_entry["Item"]["User"] == "janedoe"

    client = maskinporten_get_client_response
    assert audit_notify_matcher.last_request.json() == _slack_message_payload(
        "Client deleted",
        client["client_name"],
        "test",
        client["scopes"],
    )


def test_delete_client_no_body(
    maskinporten_get_client_response,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)

        audit_notify_matcher = rm.post(SLACK_WEBHOOK_URL)
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.get(f"{CLIENTS_ENDPOINT}{client_id}/jwks", json={})
        rm.delete(f"{CLIENTS_ENDPOINT}{client_id}")
        res = mock_client.delete(
            f"/clients/test/{client_id}",
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert res.status_code == 200
    data = res.json()
    assert data["client_id"] == client_id
    assert data["deleted_ssm_params"] == []

    table = mock_dynamodb.Table("maskinporten-audit-trail")
    audit_log_entry = table.get_item(Key={"Id": client_id, "Type": "client"})
    assert audit_log_entry["Item"]["Action"] == "delete"
    assert audit_log_entry["Item"]["User"] == "janedoe"

    client = maskinporten_get_client_response
    assert audit_notify_matcher.last_request.json() == _slack_message_payload(
        "Client deleted",
        client["client_name"],
        "test",
        client["scopes"],
    )


def test_delete_client_remaining_keys(
    maskinporten_get_client_response,
    maskinporten_list_client_keys_response,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)

        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_list_client_keys_response,
        )
        rm.delete(f"{CLIENTS_ENDPOINT}{client_id}")
        res = mock_client.delete(
            f"/clients/test/{client_id}",
            json={"aws_account": None, "aws_region": None},
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert res.status_code == 422


@patch("resources.maskinporten.ForeignAccountSecretsClient")
def test_delete_client_delete_from_ssm(
    MockForeignAccountSecretsClient,
    maskinporten_get_client_response,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"
    MockForeignAccountSecretsClient.return_value.delete_secrets.return_value = [
        "key_id",
        "keystore",
        "key_alias",
        "key_password",
    ]

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)

        audit_notify_matcher = rm.post(SLACK_WEBHOOK_URL)
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.get(f"{CLIENTS_ENDPOINT}{client_id}/jwks", json={})
        rm.delete(f"{CLIENTS_ENDPOINT}{client_id}")

        aws_account = "123456789876"
        aws_region = "eu-west-1"
        res = mock_client.delete(
            f"/clients/test/{client_id}",
            json={"aws_account": aws_account, "aws_region": aws_region},
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert res.status_code == 200
    data = res.json()
    assert data["client_id"] == client_id
    assert set(data["deleted_ssm_params"]) == {
        "key_id",
        "keystore",
        "key_alias",
        "key_password",
    }

    table = mock_dynamodb.Table("maskinporten-audit-trail")
    audit_log_entry = table.get_item(Key={"Id": client_id, "Type": "client"})
    assert audit_log_entry["Item"]["Action"] == "delete"
    assert audit_log_entry["Item"]["User"] == "janedoe"

    client = maskinporten_get_client_response
    assert audit_notify_matcher.last_request.json() == _slack_message_payload(
        "Client deleted",
        client["client_name"],
        "test",
        client["scopes"],
    )


@freeze_time("1970-01-01")
def test_create_client_key_to_aws(
    maskinporten_create_client_key_response,
    maskinporten_get_client_response,
    maskinporten_list_client_keys_response,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    mocker.spy(maskinporten.ForeignAccountSecretsClient, "send_secrets")

    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)

        audit_notify_matcher = rm.post(SLACK_WEBHOOK_URL)
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_list_client_keys_response,
        )
        rm.post(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_create_client_key_response,
        )

        destination_aws_account = "123456789876"
        destination_aws_region = "eu-west-1"
        res = mock_client.post(
            f"/clients/test/{client_id}/keys",
            json={
                "destination_aws_account": destination_aws_account,
                "destination_aws_region": destination_aws_region,
                "enable_auto_rotate": False,
            },
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert res.status_code == 201
    key = res.json()
    assert key == {
        "kid": "kid-1970-01-01-01-00-00",
        "ssm_params": [
            f"/okdata/maskinporten/{client_id}/key_id",
            f"/okdata/maskinporten/{client_id}/keystore",
            f"/okdata/maskinporten/{client_id}/key_alias",
            f"/okdata/maskinporten/{client_id}/key_password",
        ],
        "keystore": None,
        "key_alias": None,
        "key_password": None,
    }

    maskinporten.ForeignAccountSecretsClient.send_secrets.assert_called_once()
    assert {
        s["name"]
        for s in maskinporten.ForeignAccountSecretsClient.send_secrets.call_args[0][1:][
            0
        ]
    } == {"key_id", "keystore", "key_alias", "key_password"}

    table = mock_dynamodb.Table("maskinporten-audit-trail")
    audit_log_entry = table.get_item(Key={"Id": client_id, "Type": "client"})
    assert audit_log_entry["Item"]["Action"] == "add-key"
    assert audit_log_entry["Item"]["KeyId"] == key["kid"]

    client = maskinporten_get_client_response
    assert audit_notify_matcher.last_request.json() == _slack_message_payload(
        "Client key added",
        client["client_name"],
        "test",
        client["scopes"],
    )


@freeze_time("1970-01-01")
def test_create_client_key_auto_rotate(
    maskinporten_create_client_key_response,
    maskinporten_get_client_response,
    maskinporten_list_client_keys_response,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)

        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_list_client_keys_response,
        )
        rm.post(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_create_client_key_response,
        )
        res = mock_client.post(
            f"/clients/test/{client_id}/keys",
            json={
                "destination_aws_account": "123456789876",
                "destination_aws_region": "eu-west-1",
                "enable_auto_rotate": True,
            },
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert res.status_code == 201

    table = mock_dynamodb.Table("maskinporten-key-rotation")
    item = table.get_item(Key={"ClientId": client_id, "Env": "test"})["Item"]
    assert item["AwsAccount"] == "123456789876"
    assert item["AwsRegion"] == "eu-west-1"
    assert item["LastUpdated"] == "1970-01-01T00:00:00+00:00"
    assert item["ClientName"] == "my-team-freg-testing"


@freeze_time("1970-01-01")
def test_create_client_key_return_to_client(
    maskinporten_create_client_key_response,
    maskinporten_get_client_response,
    maskinporten_list_client_keys_response,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    mocker.spy(maskinporten.ForeignAccountSecretsClient, "send_secrets")
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)

        audit_notify_matcher = rm.post(SLACK_WEBHOOK_URL)
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_list_client_keys_response,
        )
        rm.post(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_create_client_key_response,
        )
        res = mock_client.post(
            f"/clients/test/{client_id}/keys",
            json={},
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert res.status_code == 201
    key = res.json()
    assert key["kid"] == "kid-1970-01-01-01-00-00"
    assert not key["ssm_params"]
    assert isinstance(key["keystore"], str)
    assert isinstance(key["key_alias"], str)
    assert isinstance(key["key_password"], str)

    maskinporten.ForeignAccountSecretsClient.send_secrets.assert_not_called()

    table = mock_dynamodb.Table("maskinporten-audit-trail")
    audit_log_entry = table.get_item(Key={"Id": client_id, "Type": "client"})
    assert audit_log_entry["Item"]["Action"] == "add-key"
    assert audit_log_entry["Item"]["KeyId"] == key["kid"]

    client = maskinporten_get_client_response
    assert audit_notify_matcher.last_request.json() == _slack_message_payload(
        "Client key added",
        client["client_name"],
        "test",
        client["scopes"],
    )


def test_create_client_key_too_many_keys(
    maskinporten_get_client_response,
    maskinporten_list_client_keys_response,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"

    # Fill up the key chain.
    maskinporten_list_client_keys_response["keys"] = (
        maskinporten_list_client_keys_response["keys"] * 5
    )

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_list_client_keys_response,
        )

        res = mock_client.post(
            f"/clients/test/{client_id}/keys",
            json={
                "destination_aws_account": "123456789876",
                "destination_aws_region": "eu-west-1",
                "enable_auto_rotate": False,
            },
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert res.status_code == 409
    assert (
        res.json()["message"]
        == f"Client '{client_id}' already has the maximum number of registered keys: 5"
    )


def test_create_client_key_invalid_client_id(mock_authorizer, mock_client):
    res = mock_client.post(
        "/clients/test/invalid_client_id/keys",
        json={
            "destination_aws_account": "123456789876",
            "destination_aws_region": "eu-west-1",
            "enable_auto_rotate": False,
        },
        headers={"Authorization": get_mock_user("janedoe").bearer_token},
    )
    assert res.status_code == 400
    assert (
        res.json()["message"]
        == 'Invalid client ID (string does not match regex "^[0-9a-f-]+$")'
    )


def test_create_client_key_assume_role_access_denied(
    mock_client,
    mock_aws,
    mock_authorizer,
    raise_assume_role_access_denied,
    maskinporten_get_client_response,
    maskinporten_create_client_key_response,
    mocker,
):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.post(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_create_client_key_response,
        )

        destination_aws_account = "123456789876"
        destination_aws_region = "eu-west-1"

        response = mock_client.post(
            f"/clients/test/{client_id}/keys",
            json={
                "destination_aws_account": destination_aws_account,
                "destination_aws_region": destination_aws_region,
                "enable_auto_rotate": False,
            },
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert response.status_code == 422
    assert response.json() == {
        "message": "Error message from aws",
    }


def test_delete_client_key_last_remaining(
    maskinporten_get_client_response,
    maskinporten_list_client_keys_response,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"
    key_id = "kid-1970-01-01-01-00-00"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)

        audit_notify_matcher = rm.post(SLACK_WEBHOOK_URL)
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_list_client_keys_response,
        )
        rm.delete(f"{CLIENTS_ENDPOINT}{client_id}/jwks")

        res = mock_client.delete(
            f"/clients/test/{client_id}/keys/{key_id}",
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert res.status_code == 200

    table = mock_dynamodb.Table("maskinporten-audit-trail")
    audit_log_entry = table.get_item(Key={"Id": client_id, "Type": "client"})
    assert audit_log_entry["Item"]["Action"] == "remove-key"
    assert audit_log_entry["Item"]["KeyId"] == key_id

    client = maskinporten_get_client_response
    assert audit_notify_matcher.last_request.json() == _slack_message_payload(
        "Client key removed",
        client["client_name"],
        "test",
        client["scopes"],
    )


def test_delete_client_key_more_than_one_left(
    maskinporten_get_client_response,
    maskinporten_list_client_keys_response,
    maskinporten_delete_client_key_response,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"
    key_id = "kid-1970-01-01-01-00-00"

    # Add a second key.
    maskinporten_list_client_keys_response["keys"].append(
        {"kid": "kid-1980-01-01-12-00-00"}
    )

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)

        audit_notify_matcher = rm.post(SLACK_WEBHOOK_URL)
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_list_client_keys_response,
        )
        rm.post(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_delete_client_key_response,
        )
        res = mock_client.delete(
            f"/clients/test/{client_id}/keys/{key_id}",
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert res.status_code == 200

    table = mock_dynamodb.Table("maskinporten-audit-trail")
    audit_log_entry = table.get_item(Key={"Id": client_id, "Type": "client"})
    assert audit_log_entry["Item"]["Action"] == "remove-key"
    assert audit_log_entry["Item"]["KeyId"] == key_id

    client = maskinporten_get_client_response
    assert audit_notify_matcher.last_request.json() == _slack_message_payload(
        "Client key removed",
        client["client_name"],
        "test",
        client["scopes"],
    )


def test_delete_client_key_no_keys(
    maskinporten_get_client_response,
    maskinporten_list_client_keys_response,
    maskinporten_delete_client_key_response,
    mock_authorizer,
    mock_aws,
    mock_client,
    mock_dynamodb,
    mocker,
):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"
    key_id = "kid-1970-01-01-01-00-00"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}",
            json=maskinporten_get_client_response,
        )
        rm.get(f"{CLIENTS_ENDPOINT}{client_id}/jwks", json={})
        res = mock_client.delete(
            f"/clients/test/{client_id}/keys/{key_id}",
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert res.status_code == 404


def test_list_client_keys(
    mock_client, mock_authorizer, maskinporten_list_client_keys_response
):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.get(
            f"{CLIENTS_ENDPOINT}{client_id}/jwks",
            json=maskinporten_list_client_keys_response,
        )
        response = mock_client.get(
            f"/clients/test/{client_id}/keys",
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert response.status_code == 200
    assert response.json() == [
        {
            "kid": "kid-1970-01-01-01-00-00",
            "client_id": client_id,
            "created": "2021-09-16T12:34:17.099000+02:00",
            "expires": "2022-09-16T12:34:17.099000+02:00",
            "last_updated": "2021-09-16T12:34:17.099000+02:00",
        }
    ]


def test_list_client_keys_no_permission_for_resource(mock_client, mock_authorizer):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        rm.get(f"{CLIENTS_ENDPOINT}{client_id}/jwks", json={"foo": "bar"})
        response = mock_client.get(
            f"/clients/test/{client_id}/keys",
            headers={"Authorization": get_mock_user("homersimpson").bearer_token},
        )

    assert response.status_code == 403
    assert response.json()["message"] == "Forbidden"


@pytest.fixture
def raise_assume_role_access_denied(monkeypatch):
    def init(self, *args, **kwargs):
        raise maskinporten.AssumeRoleAccessDeniedError("Error message from aws")

    monkeypatch.setattr(maskinporten.ForeignAccountSecretsClient, "__init__", init)
