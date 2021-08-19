import json

from aws_xray_sdk.core import patch_all, xray_recorder
from okdata.aws.logging import logging_wrapper, log_add

patch_all()


@logging_wrapper
@xray_recorder.capture("get_boilerplate")
def get_boilerplate(event, context):
    body = "Hello, world from Boilerplate!"
    ret = {"boilerplate": body}
    headers = {}
    log_add(relevant_information="Hello world from Boilerplate")
    return {"statusCode": 200, "headers": headers, "body": json.dumps(ret)}
