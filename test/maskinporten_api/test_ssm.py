import boto3
import pytest
from botocore.exceptions import ClientError
from moto.sts.models import STSBackend

from maskinporten_api.ssm import (
    SendSecretsService,
    Secrets,
    AssumeRoleAccessDeniedException,
)


def test_send_secrets(mock_aws):

    maskinporten_client_id = "some-client"
    destination_aws_region = "eu-west-1"

    SendSecretsService().send_secrets(
        Secrets("some-value", "some-value", "some-value"),
        maskinporten_client_id,
        "123456789876",
        destination_aws_region,
    )

    ssm_client = boto3.client("ssm", region_name=destination_aws_region)

    parameter_metadata = ssm_client.describe_parameters()

    assert all(
        [param["Type"] == "SecureString" for param in parameter_metadata["Parameters"]]
    )
    parameter_names = [param["Name"] for param in parameter_metadata["Parameters"]]
    expected_parameter_names = [
        f"/okdata/maskinporten/{maskinporten_client_id}/keystore",
        f"/okdata/maskinporten/{maskinporten_client_id}/key_id",
        f"/okdata/maskinporten/{maskinporten_client_id}/key_password",
    ]

    assert expected_parameter_names.sort() == parameter_names.sort()


def test_send_secrets_fails(raise_assume_role_access_denied):
    maskinporten_client_id = "some-client"
    destination_aws_region = "eu-west-1"

    with pytest.raises(AssumeRoleAccessDeniedException) as e:
        SendSecretsService().send_secrets(
            Secrets("some-value", "some-value", "some-value"),
            maskinporten_client_id,
            "123456789876",
            destination_aws_region,
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
