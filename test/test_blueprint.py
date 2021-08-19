import json

import boilerplate.handler as boilerplate_handler


from aws_xray_sdk.core import xray_recorder

xray_recorder.begin_segment("Test")


class TestBlueprint:
    def test_get_boilerplate(self):
        response = boilerplate_handler.get_boilerplate({}, {})
        body = json.loads(response["body"])
        assert response["statusCode"] == 200
        assert body["boilerplate"] == "Hello, world from Boilerplate!"
