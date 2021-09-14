from typing import Optional, Dict
from pydantic import BaseModel


class ErrorResponse(Exception):
    def __init__(self, status_code: int, message: Optional[str] = None):
        self.status_code = status_code
        self.message = message


class Message(BaseModel):
    message: Optional[str]


# TODO Needs Python 3.8
# class MessageDict(TypedDict):
#     model: ErrorResponse


def error_message_models(*status_codes) -> Dict:
    return {code: {"model": Message} for code in status_codes}
