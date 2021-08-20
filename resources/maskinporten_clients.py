import logging
import os

from fastapi import APIRouter, status

from models import MaskinportenClient

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))


router = APIRouter()


@router.post("", status_code=status.HTTP_201_CREATED)
def create_client(body: MaskinportenClient):
    # TODO: Implement real functionality
    return body
