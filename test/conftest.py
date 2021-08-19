import pytest

from fastapi.testclient import TestClient

from app import app


@pytest.fixture
def mock_client():
    app.debug = True
    return TestClient(app)
