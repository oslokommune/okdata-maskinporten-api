from maskinporten_api.maskinporten_client import EnvConfig


def mock_access_token_generation_requests(mocker):
    mocker.get(
        EnvConfig("dig", "test").oidc_wellknown,
        json={
            "token_endpoint": "https://test.maskinporten.no/token-endpoint-test",
        },
    )
    mocker.post(
        "https://test.maskinporten.no/token-endpoint-test",
        json={
            "access_token": "access_token",
            "token_type": "Bearer",
            "expires_in": 119,
            "scope": "foo:bar.read",
        },
    )
