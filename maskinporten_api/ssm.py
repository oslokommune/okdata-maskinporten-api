import os
from dataclasses import dataclass, asdict

import boto3


def get_secret(key):
    """Return a secret (SecureString) from SSM stored under `key`."""
    client = boto3.client("ssm", region_name=os.environ["AWS_REGION"])
    response = client.get_parameter(Name=key, WithDecryption=True)
    return response["Parameter"]["Value"]


@dataclass
class Secrets:
    keystore: str
    key_id: str
    key_password: str


class SSMService:
    def send_secrets(
        self, secrets: Secrets, maskinporten_client_id, destination_aws_account_id
    ):
        """Send secret values to another AWS Account.

        Secret values are stored as SecureString SSM parameters with prefix
        '/okdata/maskinporten/`maskinporten_client_id`/' in AWS account with ID
        `destination_aws_account_id`.
        """

        sts_client = boto3.client("sts")
        role_arn = (
            f"arn:aws:iam::{destination_aws_account_id}:role/dataplatform-maskinporten"
        )

        assume_role_response = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName="dataplatform-maskinporten"
        )

        credentials = assume_role_response["Credentials"]

        ssm_client = boto3.client(
            "ssm",
            region_name=os.environ["AWS_REGION"],
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )

        for key, value in asdict(secrets).items():
            ssm_client.put_parameter(
                Name=f"/okdata/maskinporten/{maskinporten_client_id}/{key}",
                Value=value,
                Type="SecureString",
            )
