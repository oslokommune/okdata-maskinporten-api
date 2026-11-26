from datetime import datetime, timezone
from unittest.mock import call, patch

from jobs.backup import export_tables


def _table_arn(table_name):
    return f"arn:aws:dynamodb:eu-west-1:123456789000:table/{table_name}"


@patch("jobs.backup.boto3")
def test_export_tables(mock_boto3):
    dynamodb = mock_boto3.client.return_value
    dynamodb.describe_table.side_effect = lambda TableName: {
        "Table": {"TableArn": _table_arn(TableName)}
    }
    dynamodb.export_table_to_point_in_time.side_effect = lambda **kwargs: {
        "ExportDescription": {
            "ExportStatus": "IN_PROGRESS",
            "S3Bucket": kwargs["S3Bucket"],
            "S3Prefix": kwargs["S3Prefix"],
        }
    }

    now = datetime.now(timezone.utc)
    export_tables({}, {})

    assert dynamodb.export_table_to_point_in_time.call_args_list == [
        call(
            TableArn=_table_arn(table_name),
            S3Bucket="backup-bucket",
            S3Prefix=f"okdata-maskinporten-api/{table_name}/{now.year}-{now.month}/",
            ExportFormat="DYNAMODB_JSON",
        )
        for table_name in ["maskinporten-audit-trail", "maskinporten-key-rotation"]
    ]
