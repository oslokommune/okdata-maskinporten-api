import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from maskinporten_api.keys import Key


class AssumeRoleAccessDeniedError(Exception):
    """Raised when access is denied when assuming an AWS role."""

    pass


class ForeignAccountSecretsClient:
    def __init__(self, aws_account, aws_region, client_id):
        try:
            assume_role_response = boto3.client("sts").assume_role(
                RoleArn=f"arn:aws:iam::{aws_account}:role/dataplatform-maskinporten",
                RoleSessionName="dataplatform-maskinporten",
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                raise AssumeRoleAccessDeniedError(e.response["Error"]["Message"])
            raise e

        credentials = assume_role_response["Credentials"]

        self.ssm_client = boto3.client(
            "ssm",
            region_name=aws_region,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
        self.client_id = client_id

    def ssm_path(self, key):
        return f"/okdata/maskinporten/{self.client_id}/{key}"

    def _send_secret(self, key, value, description):
        """Send a secret value to another AWS account.

        Return the path of the created SSM parameter.
        """
        path = self.ssm_path(key)
        self.ssm_client.put_parameter(
            Name=path,
            Value=value,
            Description=description,
            Type="SecureString",
            Overwrite=True,
        )
        return path

    def delete_secrets(self, secrets):
        """Delete secrets belonging to a Maskinporten client.

        Return a list of the deleted secrets.
        """
        return self.ssm_client.delete_parameters(
            Names=[self.ssm_path(s) for s in secrets]
        )["DeletedParameters"]

    def send_key_to_aws(self, key: Key, env, client_name):
        exp = datetime.fromtimestamp(int(key.jwk["exp"]), tz=timezone.utc)

        return [
            self._send_secret(
                "key.json",
                json.dumps(
                    {
                        "key_id": key.jwk["kid"],
                        "keystore": key.keystore,
                        "key_alias": key.alias,
                        "key_password": key.password,
                        "key_expiry": exp.isoformat(),
                    }
                ),
                (
                    f"[{env}] {client_name}: JSON-encoded string containing "
                    "the key ID, the PKCS #12 archive with the key, the alias "
                    "of the key in the keystore, the key password, and the "
                    "key expiration time."
                ),
            )
        ]
