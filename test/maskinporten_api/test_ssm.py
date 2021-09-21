import boto3

from moto import mock_sts, mock_ssm

from maskinporten_api.ssm import SSMService, Secrets


@mock_sts
@mock_ssm
def test_send_secrets():
    ssm_service = SSMService()

    maskinporten_client_id = "some-client"
    destination_aws_region = "eu-west-1"
    ssm_service.send_secrets(
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
