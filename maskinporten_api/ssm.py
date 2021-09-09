import os

import boto3


def get_secret(key):
    """Return a secret (SecureString) from SSM stored under `key`."""
    client = boto3.client("ssm", region_name=os.environ["AWS_REGION"])
    response = client.get_parameter(Name=key, WithDecryption=True)
    return response["Parameter"]["Value"]
