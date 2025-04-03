import logging
import os

import boto3
from fastapi import APIRouter, Depends, status

from maskinporten_api.db_util import query_all
from maskinporten_api.util import getenv
from models import Scope
from resources.authorizer import AuthInfo
from resources.errors import error_message_models

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))


router = APIRouter()


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    response_model=list[Scope],
    responses=error_message_models(status.HTTP_401_UNAUTHORIZED),
)
def get_scopes(auth_info: AuthInfo = Depends()):
    dynamodb = boto3.resource("dynamodb", region_name=getenv("AWS_REGION"))
    scopes = query_all(dynamodb.Table("maskinporten-scopes"))

    return [Scope(provider_id=s["ProviderId"], scope=s["Scope"]) for s in scopes]
