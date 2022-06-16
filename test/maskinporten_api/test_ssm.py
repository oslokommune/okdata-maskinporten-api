import boto3
import pytest
from botocore.exceptions import ClientError
from moto.sts.models import STSBackend

from maskinporten_api.ssm import (
    AssumeRoleAccessDeniedError,
    ForeignAccountSecretsClient,
)


def test_send_secrets(mock_aws):
    maskinporten_client_id = "some-client"
    destination_aws_region = "eu-west-1"
    secrets_client = ForeignAccountSecretsClient(
        "123456789876", destination_aws_region, maskinporten_client_id
    )

    secrets_client.send_secrets(
        [
            {"name": "some-secret-1", "value": "value", "description": "foo"},
            {"name": "some-secret-2", "value": "value", "description": "foo"},
        ]
    )

    ssm_client = boto3.client("ssm", region_name=destination_aws_region)

    okdata_parameters = [
        p
        for p in ssm_client.describe_parameters()["Parameters"]
        if p["Name"].startswith("/okdata/")
    ]

    assert all([p["Type"] == "SecureString" for p in okdata_parameters])

    assert {p["Name"] for p in okdata_parameters} == {
        f"/okdata/maskinporten/{maskinporten_client_id}/some-secret-1",
        f"/okdata/maskinporten/{maskinporten_client_id}/some-secret-2",
    }


def test_send_secrets_fails(raise_assume_role_access_denied):
    maskinporten_client_id = "some-client"
    destination_aws_region = "eu-west-1"

    with pytest.raises(AssumeRoleAccessDeniedError) as e:
        ForeignAccountSecretsClient(
            "123456789876", destination_aws_region, maskinporten_client_id
        )
        assert str(e) == "Some error"


def test_delete_secrets(mock_aws):
    maskinporten_client_id = "some-client"
    destination_aws_region = "eu-west-1"
    secrets_client = ForeignAccountSecretsClient(
        "123456789876", destination_aws_region, maskinporten_client_id
    )

    secrets_client.send_secrets(
        [
            {"name": "secret-1", "value": "value", "description": "foo"},
            {"name": "secret-2", "value": "value", "description": "foo"},
        ]
    )

    assert secrets_client.delete_secrets(["secret-1", "secret-3"]) == [
        f"/okdata/maskinporten/{maskinporten_client_id}/secret-1"
    ]

    ssm_client = boto3.client("ssm", region_name=destination_aws_region)

    okdata_parameters = {
        p["Name"]
        for p in ssm_client.describe_parameters()["Parameters"]
        if p["Name"].startswith("/okdata/")
    }

    assert okdata_parameters == {
        f"/okdata/maskinporten/{maskinporten_client_id}/secret-2",
    }


@pytest.fixture
def raise_assume_role_access_denied(monkeypatch):
    def assume_role(self, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Some error"}},
            "sts:assumeRole",
        )

    monkeypatch.setattr(STSBackend, "assume_role", assume_role)
