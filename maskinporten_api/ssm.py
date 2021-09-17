import os

import boto3


def get_secret(key):
    """Return a secret (SecureString) from SSM stored under `key`."""
    client = boto3.client("ssm", region_name=os.environ["AWS_REGION"])
    response = client.get_parameter(Name=key, WithDecryption=True)
    return response["Parameter"]["Value"]


def send_secret(secret_value, ssm_parameter_name, destination_aws_account_id):
    """Store a secret value `secret_value` as a SecureString SSM parameter with name '/okdata/maskinporten/`ssm_parameter_name`' in AWS account with ID `destination_aws_account_id`"""
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

    ssm_client.put_parameter(
        Name=f"/okdata/maskinporten/{ssm_parameter_name}",
        Value=secret_value,
        Type="SecureString",
    )
