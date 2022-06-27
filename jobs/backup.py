import os
from datetime import datetime

import boto3
from aws_xray_sdk.core import patch_all, xray_recorder
from okdata.aws.logging import log_add, logging_wrapper


BACKUP_BUCKET_NAME = os.environ["BACKUP_BUCKET_NAME"]
BACKUP_BUCKET_PREFIX = os.environ["SERVICE_NAME"] + "/maskinporten-audit-trail"

patch_all()


@logging_wrapper
@xray_recorder.capture("export_audit_trail")
def export_audit_trail(event, context):
    """Trigger export of the audit trail database to S3."""
    dynamodb = boto3.client("dynamodb", region_name=os.environ["AWS_REGION"])
    audit_trail_table = dynamodb.describe_table(TableName="maskinporten-audit-trail")
    dt_now = datetime.utcnow()
    s3_prefix = f"{BACKUP_BUCKET_PREFIX}/{dt_now.year}-{dt_now.month}/"

    export_response = dynamodb.export_table_to_point_in_time(
        TableArn=audit_trail_table["Table"]["TableArn"],
        S3Bucket=BACKUP_BUCKET_NAME,
        S3Prefix=s3_prefix,
        ExportFormat="DYNAMODB_JSON",
    )["ExportDescription"]

    log_add(
        s3_export_status=export_response["ExportStatus"],
        s3_export_target_bucket=export_response["S3Bucket"],
        s3_export_target_prefix=export_response["S3Prefix"],
    )
