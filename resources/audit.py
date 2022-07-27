import logging
import os

from fastapi import APIRouter, Depends, Path, status

from maskinporten_api.audit import audit_log_for_client
from maskinporten_api.permissions import client_resource_name
from models import AuditLogEntry, MaskinportenEnvironment
from resources.authorizer import AuthInfo, authorize
from resources.errors import error_message_models

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))

router = APIRouter()


@router.get(
    "/{env}/{client_id}/log",
    status_code=status.HTTP_200_OK,
    response_model=list[AuditLogEntry],
    responses=error_message_models(
        status.HTTP_400_BAD_REQUEST,
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    ),
)
def get_audit_log(
    env: MaskinportenEnvironment,
    client_id: str = Path(..., regex=r"^[0-9a-f-]+$"),
    auth_info: AuthInfo = Depends(),
):
    authorize(
        auth_info,
        scope="maskinporten:client:read",
        resource=client_resource_name(env, client_id),
    )

    return [
        AuditLogEntry(
            item_id=item["Id"],
            timestamp=item["Timestamp"],
            action=item["Action"],
            user=item["User"],
            scopes=item["Scopes"].split(",") if "Scopes" in item else None,
            key_id=item.get("KeyId"),
        )
        for item in audit_log_for_client(env, client_id)
    ]
