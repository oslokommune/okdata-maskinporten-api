from typing import Optional, Dict

from pydantic import BaseModel

from models import MaskinportenEnvironment


class ErrorResponse(Exception):
    def __init__(self, status_code: int, message: Optional[str] = None):
        self.status_code = status_code
        self.message = message


class Message(BaseModel):
    message: Optional[str]


def error_message_models(*status_codes) -> Dict:
    return {code: {"model": Message} for code in status_codes}


def pydantic_error_to_str(err):
    # Tailor made message for the case when an invalid Maskinporten environment
    # is given.
    if err["loc"] == ("path", "env"):
        return "Unsupported Maskinporten environment. Must be one of: {}".format(
            ", ".join([e.value for e in MaskinportenEnvironment])
        )

    # Fall back to Pydantic's default in the general case.
    return str(err)
