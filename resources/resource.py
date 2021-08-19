import logging
import os

from fastapi import APIRouter

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))


router = APIRouter()


@router.get("")
def get_resource():
    return {"message": "Hello maskinporten!"}
