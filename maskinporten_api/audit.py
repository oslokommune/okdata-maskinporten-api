import logging
import time
from datetime import datetime, timezone

import boto3
import requests
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from okdata.aws.ssm import get_secret

from maskinporten_api.permissions import client_resource_name

log = logging.getLogger()


_TABLE_NAME = "maskinporten-audit-trail"


def _query_all(table, **query):
    """Return every result from `table` by evaluating `query`."""
    res = table.query(**query)
    items = res["Items"]

    while "LastEvaluatedKey" in res:
        time.sleep(1)  # Let's be nice
        res = table.query(ExclusiveStartKey=res["LastEvaluatedKey"], **query)
        items.extend(res["Items"])

    return items


def audit_log(item_id, action, user, scopes=None, key_id=None):
    """Add a log entry to the API's audit trail."""

    dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
    table = dynamodb.Table(_TABLE_NAME)

    try:
        db_response = table.put_item(
            Item={
                "Id": item_id,
                "Timestamp": datetime.now(timezone.utc).isoformat(),
                "Action": action,
                "User": user,
                **({"Scopes": ",".join(scopes)} if scopes else {}),
                **({"KeyId": key_id} if key_id else {}),
            }
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        log.error(f"Error creating audit log ({error_code}): {msg}")
        return None

    status_code = db_response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code != 200:
        log.error(f"Error creating audit log ({status_code}): {db_response}")
        return None

    return db_response


def audit_notify(header, client_name, env, scopes):
    try:
        notify_endpoint = get_secret(
            "/dataplatform/slack/maskinporten-api-slack-webhook"
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            log.warning("No notify endpoint configured")
            return
        raise

    try:
        response = requests.post(
            notify_endpoint,
            json=_slack_message_payload(header, client_name, env, scopes),
        )
        response.raise_for_status()
    except requests.RequestException as e:
        status_code = getattr(e.response, "status_code", None)
        log.error(
            "Notification request failed{}".format(
                f" ({status_code})" if status_code else ""
            )
        )


def _slack_message_payload(header, client_name, env, scopes):
    line_separated_scopes = "\n".join(scopes)
    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": header,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Client:*\n{client_name}"},
                    {"type": "mrkdwn", "text": f"*Environment:*\n{env}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Scopes:*\n{line_separated_scopes}",
                },
            },
        ]
    }


def audit_log_for_client(env, client_id):
    dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")

    return _query_all(
        dynamodb.Table(_TABLE_NAME),
        KeyConditionExpression=Key("Id").eq(
            client_resource_name(env, client_id),
        ),
    )
