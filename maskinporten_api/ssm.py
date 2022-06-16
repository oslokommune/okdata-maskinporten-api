import os

import boto3
from botocore.exceptions import ClientError


def get_secret(key):
    """Return a secret (SecureString) from SSM stored under `key`."""
    client = boto3.client("ssm", region_name=os.environ["AWS_REGION"])
    response = client.get_parameter(Name=key, WithDecryption=True)
    return response["Parameter"]["Value"]


class AssumeRoleAccessDeniedError(Exception):
    """Raised when access is denied when assuming an AWS role."""

    pass


class ForeignAccountSecretsClient:
    def __init__(self, aws_account, aws_region, client_id):
        try:
            assume_role_response = boto3.client("sts").assume_role(
                RoleArn=f"arn:aws:iam::{aws_account}:role/dataplatform-maskinporten",
                RoleSessionName="dataplatform-maskinporten",
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                raise AssumeRoleAccessDeniedError(e.response["Error"]["Message"])
            raise e

        credentials = assume_role_response["Credentials"]

        self.ssm_client = boto3.client(
            "ssm",
            region_name=aws_region,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
        self.client_id = client_id

    def ssm_path(self, key):
        return f"/okdata/maskinporten/{self.client_id}/{key}"

    def _send_secret(self, key, value, description):
        """Send a secret value to another AWS account.

        Return the path of the created SSM parameter.
        """
        path = self.ssm_path(key)
        self.ssm_client.put_parameter(
            Name=path,
            Value=value,
            Description=description,
            Type="SecureString",
            Overwrite=True,
        )
        return path

    def send_secrets(self, secrets: list):
        """Send secret values to another AWS account.

        Secret values are stored as SecureString SSM parameters with prefix
        `/okdata/maskinporten/{self.client_id}/`.

        Return a list of the paths of the created SSM parameters.
        """
        return [
            self._send_secret(
                s["name"],
                s["value"],
                s["description"],
            )
            for s in secrets
        ]

    def delete_secrets(self, secrets):
        """Delete secrets belonging to a Maskinporten client.

        Return a list of the deleted secrets.
        """
        return self.ssm_client.delete_parameters(
            Names=[self.ssm_path(s) for s in secrets]
        )["DeletedParameters"]
