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

    secrets_client.send_secrets({"some-secret-1": "value", "some-secret-2": "value"})

    ssm_client = boto3.client("ssm", region_name=destination_aws_region)

    parameter_metadata = ssm_client.describe_parameters()

    assert all(
        [param["Type"] == "SecureString" for param in parameter_metadata["Parameters"]]
    )
    parameter_names = [param["Name"] for param in parameter_metadata["Parameters"]]
    expected_parameter_names = [
        f"/okdata/maskinporten/{maskinporten_client_id}/some-secret-1",
        f"/okdata/maskinporten/{maskinporten_client_id}/some-secret-2",
    ]

    assert expected_parameter_names.sort() == parameter_names.sort()


def test_send_secrets_fails(raise_assume_role_access_denied):
    maskinporten_client_id = "some-client"
    destination_aws_region = "eu-west-1"

    with pytest.raises(AssumeRoleAccessDeniedError) as e:
        ForeignAccountSecretsClient(
            "123456789876", destination_aws_region, maskinporten_client_id
        )
        assert str(e) == "Some error"


@pytest.fixture
def raise_assume_role_access_denied(monkeypatch):
    def assume_role(self, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Some error"}},
            "sts:assumeRole",
        )

    monkeypatch.setattr(STSBackend, "assume_role", assume_role)
