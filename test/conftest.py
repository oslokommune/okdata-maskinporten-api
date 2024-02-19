import os

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_dynamodb, mock_ssm, mock_sts

from app import app
from models import MaskinportenEnvironment


@pytest.fixture
def mock_client():
    app.debug = True
    return TestClient(app)


@pytest.fixture
def mock_aws():
    mock_ssm().start()
    mock_sts().start()

    # Add required values to parameter_store
    initialize_parameter_store()


def initialize_parameter_store():
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


@pytest.fixture
@mock_dynamodb
def mock_dynamodb():
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
    return dynamodb
