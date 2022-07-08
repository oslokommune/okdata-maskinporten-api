"""Automatic Maskinporten client key rotation job."""

import io
import logging
import os
import threading
import time
import traceback

from aws_xray_sdk.core import patch_all, xray_recorder
from okdata.aws.logging import log_add, logging_wrapper

from maskinporten_api.auto_rotate import clients_to_rotate
from maskinporten_api.keys import create_key
from maskinporten_api.maskinporten_client import MaskinportenClient
from maskinporten_api.ssm import ForeignAccountSecretsClient
from maskinporten_api.util import getenv
from models import MaskinportenEnvironment

patch_all()

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))

MASKINPORTEN_ENVS = [e.value for e in MaskinportenEnvironment]


class FailedClientsError(Exception):
    """Raised if rotation failed for any of the scheduled clients."""

    pass


class DeleteKey(threading.Thread):
    """Thread for deleting a given key after a certain grace period."""

    def __init__(self, maskinporten_client, env, client_id, kid):
        self.maskinporten_client = maskinporten_client
        self.env = env
        self.client_id = client_id
        self.kid = kid
        super().__init__()

    def run(self):
        time.sleep(int(getenv("KEY_ROTATION_GRACE_PERIOD_SECONDS")))
        self.maskinporten_client.delete_client_key(self.client_id, self.kid)
        logger.info(
            f"Deleted key '{self.kid}' from client '{self.client_id}' [{self.env}]"
        )


def _rotate_client(
    maskinporten_client, client_id, env, aws_account, aws_region, client_name
):
    """Rotate keys for a client.

    Creates a new key in SSM and schedules deletion of any existing ones.
    """

    logger.info(f"Assuming IAM role for {aws_account}")
    secrets_client = ForeignAccountSecretsClient(
        aws_account,
        aws_region,
        client_id,
    )

    key = create_key()
    existing_keys = (
        maskinporten_client.get_client_keys(client_id).json().get("keys", [])
    )

    logger.info(f"Creating a new key '{key.jwk['kid']}'")
    maskinporten_client.create_client_key(client_id, key.jwk).json()

    secrets_client.send_key_to_aws(key, env, client_name)

    logger.info("Scheduling old keys for deletion")
    for kid in [jwk["kid"] for jwk in existing_keys]:
        t = DeleteKey(maskinporten_client, env, client_id, kid)
        t.start()
        logger.info(f"Scheduled '{kid}' for deletion")
        yield t


@logging_wrapper
@xray_recorder.capture("client_report")
def rotate_keys(event, context):
    maskinporten_clients = {env: MaskinportenClient(env) for env in MASKINPORTEN_ENVS}
    scheduled_deletions = []
    client_exceptions = {}

    for client in clients_to_rotate():
        logger.info(
            f"Handling client '{client['ClientName']}' [{client['Env']}]",
        )
        try:
            scheduled_deletions.extend(
                _rotate_client(
                    maskinporten_clients[client["Env"]],
                    client["ClientId"],
                    client["Env"],
                    client["AwsAccount"],
                    client["AwsRegion"],
                    client["ClientName"],
                )
            )
        except Exception as e:
            key = f"{client['Env']}-{client['ClientId']}"
            client_exceptions.setdefault(key, []).append(str(e))

    def thread_exc_handler(args, /):
        with io.StringIO() as e:
            traceback.print_exception(
                args.exc_type, args.exc_value, args.exc_traceback, file=e
            )
            key = f"{args.thread.env}-{args.thread.client_id}"
            client_exceptions.setdefault(key, []).append(e.getvalue())

    threading.excepthook = thread_exc_handler

    logger.info("Waiting for all scheduled deletions to finish...")
    for t in scheduled_deletions:
        t.join()

    logger.info("Done")

    if client_exceptions:
        log_add(client_exceptions=client_exceptions)
        raise FailedClientsError
