class TestMaskinportenClients:
    def test_get_resource(self, mock_client):
        body = {
            "name": "some-client",
            "description": "Very cool client",
            "scopes": ["some-scope"],
        }

        assert mock_client.post("/clients", json=body).json() == body
