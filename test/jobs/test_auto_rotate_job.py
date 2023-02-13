import os
from datetime import datetime, timedelta
from unittest.mock import ANY, Mock, patch

from resources import maskinporten

from jobs.auto_rotate import _rotate_client, DeleteKey, rotate_keys


def test_delete_key():
    client_id = "6507478c-d31a-d786-239c-0d9ad1c41d54"
    kid = "kid-2022-01-01-00-00-00"
    mp_client = Mock()

    t = DeleteKey(mp_client, "test", client_id, kid)
    pre_run_timestamp = datetime.now()
    t.start()
    t.join()
    post_run_timestamp = datetime.now()

    assert (
        pre_run_timestamp
        + timedelta(seconds=int(os.getenv("KEY_ROTATION_GRACE_PERIOD_SECONDS")))
        <= post_run_timestamp
    )

    mp_client.delete_client_key.assert_called_once_with(client_id, kid)


def test_rotate_client_no_existing_key(mock_aws, mocker):
    mocker.spy(maskinporten.ForeignAccountSecretsClient, "_send_secrets")
    mp_client = Mock()
    mp_client.get_client_keys.return_value.json.return_value = {"keys": []}

    scheduled_deletions = list(
        _rotate_client(
            mp_client,
            "8b1969bd-f0a7-170d-0638-a88ecedb60b3",
            "test",
            "123456789000",
            "eu-west-1",
            "my-client",
        )
    )
    assert scheduled_deletions == []

    mp_client.create_client_key.assert_called_once()
    maskinporten.ForeignAccountSecretsClient._send_secrets.assert_called_once()


def test_rotate_client_single_existing_key(mock_aws, mocker):
    mocker.spy(maskinporten.ForeignAccountSecretsClient, "_send_secrets")
    mp_client = Mock()
    mp_client.get_client_keys.return_value.json.return_value = {
        "keys": [{"kid": "key-1"}]
    }
    client_id = "8b1969bd-f0a7-170d-0638-a88ecedb60b3"

    pre_run_timestamp = datetime.now()

    scheduled_deletions = list(
        _rotate_client(
            mp_client, client_id, "test", "123456789000", "eu-west-1", "my-client"
        )
    )

    for t in scheduled_deletions:
        t.join()

    post_run_timestamp = datetime.now()

    assert (
        pre_run_timestamp
        + timedelta(seconds=int(os.getenv("KEY_ROTATION_GRACE_PERIOD_SECONDS")))
        <= post_run_timestamp
    )

    assert len(scheduled_deletions) == 1
    assert scheduled_deletions[0].maskinporten_client == mp_client
    assert scheduled_deletions[0].env == "test"
    assert scheduled_deletions[0].client_id == "8b1969bd-f0a7-170d-0638-a88ecedb60b3"
    assert scheduled_deletions[0].kid == "key-1"

    mp_client.create_client_key.assert_called_once()
    maskinporten.ForeignAccountSecretsClient._send_secrets.assert_called_once()


def test_rotate_client_multiple_existing_keys(mock_aws, mocker):
    mocker.spy(maskinporten.ForeignAccountSecretsClient, "_send_secrets")
    mp_client = Mock()
    mp_client.get_client_keys.return_value.json.return_value = {
        "keys": [{"kid": "key-1"}, {"kid": "key-2"}]
    }
    client_id = "8b1969bd-f0a7-170d-0638-a88ecedb60b3"

    pre_run_timestamp = datetime.now()

    scheduled_deletions = list(
        _rotate_client(
            mp_client, client_id, "test", "123456789000", "eu-west-1", "my-client"
        )
    )

    for t in scheduled_deletions:
        t.join()

    post_run_timestamp = datetime.now()

    # They should have waited the grace period before deleting ...
    assert (
        pre_run_timestamp
        + timedelta(seconds=int(os.getenv("KEY_ROTATION_GRACE_PERIOD_SECONDS")))
        <= post_run_timestamp
    )

    # ... but not twice (even if there are two keys to delete).
    #
    # Admittedly this test isn't guaranteed to be stable, but it seems safe
    # enough to assume that pytest won't spend more than three seconds
    # extra. Let's see whether works out in practice. If three seconds isn't
    # enough, KEY_ROTATION_GRACE_PERIOD_SECONDS could be increased a bit.
    assert (
        pre_run_timestamp
        + timedelta(seconds=int(os.getenv("KEY_ROTATION_GRACE_PERIOD_SECONDS")) * 2)
        > post_run_timestamp
    )

    assert len(scheduled_deletions) == 2

    assert scheduled_deletions[0].maskinporten_client == mp_client
    assert scheduled_deletions[0].env == "test"
    assert scheduled_deletions[0].client_id == "8b1969bd-f0a7-170d-0638-a88ecedb60b3"
    assert scheduled_deletions[0].kid == "key-1"

    assert scheduled_deletions[1].maskinporten_client == mp_client
    assert scheduled_deletions[1].env == "test"
    assert scheduled_deletions[1].client_id == "8b1969bd-f0a7-170d-0638-a88ecedb60b3"
    assert scheduled_deletions[1].kid == "key-2"

    mp_client.create_client_key.assert_called_once()
    maskinporten.ForeignAccountSecretsClient._send_secrets.assert_called_once()


@patch("jobs.auto_rotate._rotate_client")
@patch("jobs.auto_rotate.clients_to_rotate")
def test_rotate_keys(
    mock_clients_to_rotate, mock_rotate_client, mock_aws, mock_dynamodb
):
    client_id = "19ba4329-2c11-234b-a66d-69a4174e9e49"
    mock_clients_to_rotate.return_value = [
        {
            "ClientId": client_id,
            "Env": "test",
            "AwsAccount": "123456789000",
            "AwsRegion": "eu-west-1",
            "ClientName": "my-client",
        }
    ]

    rotate_keys({}, {})

    mock_rotate_client.assert_called_once_with(
        ANY, client_id, "test", "123456789000", "eu-west-1", "my-client"
    )
