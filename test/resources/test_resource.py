class TestBlueprint:
    def test_get_resource(self, mock_client):
        assert mock_client.get("/resources").json() == {
            "message": "Hello maskinporten!"
        }
