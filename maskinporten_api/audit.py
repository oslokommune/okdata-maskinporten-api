import logging
import os
from datetime import datetime, timezone

import boto3
import requests
from botocore.exceptions import ClientError

log = logging.getLogger()


def audit_log(item_id, item_type, env, action, user, scopes=None, key_id=None):
    """Add a log entry to the API's audit trail."""

    dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
    table = dynamodb.Table("maskinporten-audit-trail")

    try:
        db_response = table.put_item(
            Item={
                "Id": item_id,
                "Type": item_type,
                "Env": env,
                "Action": action,
                "User": user,
                "Timestamp": datetime.now(timezone.utc).isoformat(),
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
    notify_endpoint = os.getenv("SLACK_MASKINPORTEN_API_ALERTS_WEBHOOK_URL")

    if not notify_endpoint:
        log.warning("No notify endpoint configured")
        return

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
