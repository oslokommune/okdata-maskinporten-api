import os

import boto3
from botocore.exceptions import ClientError


def get_secret(key):
    """Return a secret (SecureString) from SSM stored under `key`."""
    client = boto3.client("ssm", region_name=os.environ["AWS_REGION"])
    response = client.get_parameter(Name=key, WithDecryption=True)
    return response["Parameter"]["Value"]


class AssumeRoleAccessDeniedException(Exception):
    """Raised when assume role request to aws fails with an access denied error"""

    pass


def send_secrets(
    secrets: dict,
    maskinporten_client_id: str,
    destination_aws_account_id: str,
    destination_aws_region: str,
):
    """Send secret values to another AWS account.

    Secret values are stored as SecureString SSM parameters with prefix
    '/okdata/maskinporten/`maskinporten_client_id`/' in AWS account with ID
    `destination_aws_account_id`.

    Return a list of the created SSM parameters.
    """
    try:
        assume_role_response = boto3.client("sts").assume_role(
            RoleArn=f"arn:aws:iam::{destination_aws_account_id}:role/dataplatform-maskinporten",
            RoleSessionName="dataplatform-maskinporten",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            raise AssumeRoleAccessDeniedException(e.response["Error"]["Message"])
        raise e

    credentials = assume_role_response["Credentials"]

    ssm_client = boto3.client(
        "ssm",
        region_name=destination_aws_region,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )

    ssm_params = []
    for key, value in secrets.items():
        path = f"/okdata/maskinporten/{maskinporten_client_id}/{key}"
        ssm_client.put_parameter(
            Name=path,
            Value=value,
            Type="SecureString",
            Overwrite=True,
        )
        ssm_params.append(path)

    return ssm_params
