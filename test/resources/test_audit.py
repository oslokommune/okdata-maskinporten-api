import requests_mock
from freezegun import freeze_time

from maskinporten_api.audit import audit_log
from maskinporten_api.permissions import client_resource_name
from test.mock_utils import mock_access_token_generation_requests
from test.resources.conftest import get_mock_user


def test_get_audit_log_empty(mock_client, mock_authorizer, mock_dynamodb):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        response = mock_client.get(
            f"/audit/test/{client_id}/log",
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert response.status_code == 200
    assert response.json() == []


@freeze_time("1970-01-01")
def test_get_audit_log_non_empty(mock_client, mock_authorizer, mock_dynamodb):
    client_id = "d1427568-1eba-1bf2-59ed-1c4af065f30e"
    audit_log(
        client_resource_name("test", client_id),
        "action",
        "user",
        ["scope-1", "scope-2"],
        "kid",
    )
    audit_log("foo", "bar", "baz")  # Should not appear in the response

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        response = mock_client.get(
            f"/audit/test/{client_id}/log",
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert response.status_code == 200
    assert response.json() == [
        {
            "id": client_resource_name("test", client_id),
            "action": "action",
            "timestamp": "1970-01-01T00:00:00+00:00",
            "user": "user",
            "scopes": ["scope-1", "scope-2"],
            "key_id": "kid",
        }
    ]


def test_get_audit_log_no_access(mock_client, mock_authorizer):
    client_id = "36fdf3f2-68c2-d131-4d10-dcc2d077771a"

    with requests_mock.Mocker(real_http=True) as rm:
        mock_access_token_generation_requests(rm)
        response = mock_client.get(
            f"/audit/test/{client_id}/log",
            headers={"Authorization": get_mock_user("janedoe").bearer_token},
        )

    assert response.status_code == 403
