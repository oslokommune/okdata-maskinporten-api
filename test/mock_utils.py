def mock_access_token_generation_requests(mocker):
    mocker.get(
        "https://example.org/.well-known/conf",
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
