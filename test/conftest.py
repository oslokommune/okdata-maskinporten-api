import os

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_ssm

from app import app


@pytest.fixture
def mock_client():
    app.debug = True
    return TestClient(app)


@pytest.fixture
def mock_boto(monkeypatch):
    mock_ssm().start()

    # Add required values to parameter_store
    initialize_parameter_store()


def initialize_parameter_store():
    ssm_client = boto3.client("ssm", region_name=os.environ["AWS_REGION"])

    ssm_client.put_parameter(
        Name=f"/dataplatform/{os.environ['SERVICE_NAME']}/keycloak-client-secret",
        Value="supersecretpassword",
        Type="SecureString",
    )
