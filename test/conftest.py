import os

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_ssm, mock_sts

from app import app


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

    with open("test/data/test.p12.txt") as f:
        ssm_client.put_parameter(
            Name="/dataplatform/maskinporten/origo-certificate-test",
            Value=f.read(),
            Type="SecureString",
        )
