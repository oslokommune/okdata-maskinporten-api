import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger()


def audit_log(item_id, item_type, env, action, user, scopes=None, client_id=None):
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
                **({"ClientId": client_id} if client_id else {}),
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
