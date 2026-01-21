"""Utilities concerning automatic key rotation."""

import logging
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from okdata.aws.logging import log_exception

from maskinporten_api.util import getenv

log = logging.getLogger()

_TABLE_NAME = "maskinporten-key-rotation"


def _log_error(client_name, error_code, msg):
    log.error(
        "Error enabling automatic key rotation for "
        f"{client_name} ({error_code}): {msg}"
    )


def clients_to_rotate():
    """Return every client entry scheduled for rotation."""

    dynamodb = boto3.resource("dynamodb", region_name=getenv("AWS_REGION"))
    table = dynamodb.Table(_TABLE_NAME)
    res = table.scan()
    items = res["Items"]

    while "LastEvaluatedKey" in res:
        time.sleep(1)  # Let's be nice
        res = table.scan(ExclusiveStartKey=res["LastEvaluatedKey"])
        items.extend(res["Items"])

    return items


def enable_auto_rotate(client_id, org, env, aws_account, aws_region, client_name):
    """Enable automatic key rotation for client `client_id`."""

    dynamodb = boto3.resource("dynamodb", region_name=getenv("AWS_REGION"))
    table = dynamodb.Table(_TABLE_NAME)

    try:
        db_response = table.put_item(
            Item={
                "ClientId": client_id,
                "Org": org,
                "Env": env,
                "AwsAccount": aws_account,
                "AwsRegion": aws_region,
                "LastUpdated": datetime.now(timezone.utc).isoformat(),
                "ClientName": client_name,
            }
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        _log_error(client_name, error_code, msg)
        log_exception(e)
        return None

    status_code = db_response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code != 200:
        _log_error(client_name, status_code, db_response)
        return None

    return db_response


def disable_auto_rotate(client_id, env):
    """Disable automatic key rotation for client `client_id` in `env`.

    Behaves as a no-op if the client hadn't enabled key rotation.
    """

    dynamodb = boto3.resource("dynamodb", region_name=getenv("AWS_REGION"))
    table = dynamodb.Table("maskinporten-key-rotation")

    try:
        db_response = table.delete_item(
            Key={"ClientId": client_id, "Env": env},
            ConditionExpression="attribute_exists(ClientId) AND attribute_exists(Env)",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return None
        error_code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        _log_error(f"{client_id} [{env}]", error_code, msg)
        log_exception(e)
        return None

    status_code = db_response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code != 200:
        _log_error(f"{client_id} [{env}]", status_code, db_response)
        return None

    return db_response


def has_auto_rotate_enabled(client_id, env):
    """Return true if key rotation is enabled for client `client_id` in `env`."""

    dynamodb = boto3.resource("dynamodb", region_name=getenv("AWS_REGION"))
    table = dynamodb.Table("maskinporten-key-rotation")

    return "Item" in table.get_item(Key={"ClientId": client_id, "Env": env})
