class TestMaskinportenClients:
    def test_create_client(self, mock_client):
        body = {
            "name": "some-client",
            "description": "Very cool client",
            "scopes": ["some-scope"],
        }

        assert mock_client.post("/clients", json=body).json() == {
            "client_id": "some-client-id",
            "name": "some-client",
            "description": "Very cool client",
            "scopes": ["some-scope"],
        }

    def test_create_client_key(self, mock_client):
        client_id = "some-client-id"

        assert mock_client.post(f"/clients/{client_id}/keys").json() == {
            "key_id": f"{client_id}-uuid",
            "key": "some-key",
        }
