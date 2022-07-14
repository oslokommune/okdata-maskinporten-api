import os
from datetime import datetime

import boto3
from aws_xray_sdk.core import patch_all, xray_recorder
from okdata.aws.logging import log_add, logging_wrapper

from maskinporten_api.util import getenv

BACKUP_BUCKET_NAME = getenv("BACKUP_BUCKET_NAME")
SERVICE_NAME = getenv("SERVICE_NAME")

TABLE_NAMES = [
    "maskinporten-audit-trail",
    "maskinporten-key-rotation",
]

patch_all()


@logging_wrapper
@xray_recorder.capture("export_tables")
def export_tables(event, context):
    """Trigger exports of Maskinporten related DynamoDB tables to S3."""
    dynamodb = boto3.client("dynamodb", region_name=os.environ["AWS_REGION"])
    dt_now = datetime.utcnow()
    results = []

    for table_name in TABLE_NAMES:
        table = dynamodb.describe_table(TableName=table_name)
        s3_prefix = f"{SERVICE_NAME}/{table_name}/{dt_now.year}-{dt_now.month}/"

        response = dynamodb.export_table_to_point_in_time(
            TableArn=table["Table"]["TableArn"],
            S3Bucket=BACKUP_BUCKET_NAME,
            S3Prefix=s3_prefix,
            ExportFormat="DYNAMODB_JSON",
        )["ExportDescription"]

        results.append(
            {
                "s3_export_status": response["ExportStatus"],
                "s3_export_target_bucket": response["S3Bucket"],
                "s3_export_target_prefix": response["S3Prefix"],
            }
        )

    log_add(results=results)
