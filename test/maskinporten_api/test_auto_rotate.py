from decimal import Decimal

from maskinporten_api.auto_rotate import (
    _TABLE_NAME,
    clients_to_rotate,
    enable_auto_rotate,
)


def test_clients_to_rotate(mock_dynamodb):
    assert len(clients_to_rotate()) == 0

    enable_auto_rotate(
        "d7376610-a253-2ee6-7b44-f8674d73e3c2",
        "test",
        123456789000,
        "eu-west-1",
        "my-client-1",
    )
    assert len(clients_to_rotate()) == 1

    enable_auto_rotate(
        "cd786784-95db-e75c-f9d6-b145be2a2a62",
        "test",
        123456789000,
        "eu-west-1",
        "my-client-2",
    )
    assert len(clients_to_rotate()) == 2


def test_enable_auto_rotate(mock_dynamodb):
    client_id = "cbf4058f-9a8b-75c5-9b19-25d6fef8e8ba"
    env = "test"

    enable_auto_rotate(client_id, env, 123456789000, "eu-west-1", "my-client")

    table = mock_dynamodb.Table(_TABLE_NAME)
    item = table.get_item(Key={"ClientId": client_id, "Env": env})["Item"]
    assert item["AwsAccount"] == Decimal("123456789000")
    assert item["AwsRegion"] == "eu-west-1"
    assert item["ClientName"] == "my-client"
