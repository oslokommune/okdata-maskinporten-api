import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger()


@dataclass
class AuditLogEntry:
    item_id: str
    item_type: str
    env: str
    action: str #
    user: str
    scopes = {}
    client_id = {}


class AuditLogger:

    def __init__(self):
        dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
        self.table = dynamodb.Table("maskinporten-audit-trail")

    def log(self, audit_log_entry: AuditLogEntry):
        """Add a log entry to the API's audit trail."""

        try:
            db_response = self.table.put_item(
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