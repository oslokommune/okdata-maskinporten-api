from maskinporten_api.maskinporten_client import EnvConfig


def mock_access_token_generation_requests(mocker):
    mocker.get(
        EnvConfig("dig", "test").oidc_wellknown,
        json={
            "issuer": "foo-corp",
            "token_endpoint": "https://example.org/token-endpoint",
        },
    )
    mocker.post(
        "https://example.org/token-endpoint",
        json={
            "access_token": "access_token",
            "token_type": "Bearer",
            "expires_in": 119,
            "scope": "foo:bar.read",
        },
    )
