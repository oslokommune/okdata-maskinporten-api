import os
import json

import boto3


def get_secret(key):
    """Return a secret (SecureString) from SSM stored under `key`."""
    client = boto3.client("ssm", region_name=os.environ["AWS_REGION"])
    response = client.get_parameter(Name=key, WithDecryption=True)
    return response["Parameter"]["Value"]


def send_key(value, name, destination_aws_account_id):
    sts_client = boto3.client("sts")
    role_arn = f"arn:aws:iam::{destination_aws_account_id}:role/dataplatform-prod-test"

    assume_role_response = sts_client.assume_role(
        RoleArn=role_arn, RoleSessionName="dataplatform-prod"
    )

    credentials = assume_role_response["Credentials"]
    access_key_id = credentials["AccessKeyId"]
    secret_access_key = credentials["SecretAccessKey"]
    session_token = credentials["SessionToken"]

    ssm_client = boto3.client(
        "ssm",
        region_name="eu-west-1",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token,
    )

    ssm_client.put_parameter(
        Name=name,
        Value=value,
        Type="SecureString",
    )
