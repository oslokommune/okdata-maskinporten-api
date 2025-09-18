import os

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from app import app
from models import MaskinportenEnvironment


@pytest.fixture
def mock_client():
    app.debug = True
    return TestClient(app)


@pytest.fixture
def mock_ssm():
    with mock_aws():
        ssm_client = boto3.client("ssm", region_name=os.environ["AWS_REGION"])

        ssm_client.put_parameter(
            Name=f"/dataplatform/{os.environ['SERVICE_NAME']}/keycloak-client-secret",
            Value="supersecretpassword",
            Type="SecureString",
        )
        ssm_client.put_parameter(
            Name="/dataplatform/slack/maskinporten-api-slack-webhook",
            Value="http://hooks.slack.arpa/services/123",
            Type="SecureString",
        )

        for env in MaskinportenEnvironment:
            ssm_client.put_parameter(
                Name=f"/dataplatform/maskinporten/origo-certificate-password-{env.value}",
                Value="test",
                Type="SecureString",
            )
            with open("test/data/test.p12.txt.part1") as f:
                ssm_client.put_parameter(
                    Name=f"/dataplatform/maskinporten/origo-certificate-{env.value}.part1",
                    Value=f.read(),
                    Type="SecureString",
                )
            with open("test/data/test.p12.txt.part2") as f:
                ssm_client.put_parameter(
                    Name=f"/dataplatform/maskinporten/origo-certificate-{env.value}.part2",
                    Value=f.read(),
                    Type="SecureString",
                )

        yield ssm_client


@pytest.fixture
def mock_ssm_foreign():
    with mock_aws():
        assume_role_response = boto3.client("sts").assume_role(
            RoleArn="arn:aws:iam::123456789876:role/dataplatform-maskinporten",
            RoleSessionName="dataplatform-maskinporten",
        )
        credentials = assume_role_response["Credentials"]
        ssm_client = boto3.client(
            "ssm",
            region_name=os.environ["AWS_REGION"],
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
        yield ssm_client


@pytest.fixture
def mock_dynamodb():
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
        dynamodb.create_table(
            TableName="maskinporten-audit-trail",
            KeySchema=[
                {"AttributeName": "Id", "KeyType": "HASH"},
                {"AttributeName": "Timestamp", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "Id", "AttributeType": "S"},
                {"AttributeName": "Timestamp", "AttributeType": "S"},
            ],
            ProvisionedThroughput={
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            },
        )
        dynamodb.create_table(
            TableName="maskinporten-key-rotation",
            KeySchema=[
                {"AttributeName": "ClientId", "KeyType": "HASH"},
                {"AttributeName": "Env", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "ClientId", "AttributeType": "S"},
                {"AttributeName": "Env", "AttributeType": "S"},
            ],
            ProvisionedThroughput={
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            },
        )
        yield dynamodb
