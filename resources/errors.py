from typing import Optional, Dict

from pydantic import BaseModel

from models import MaskinportenEnvironment


class ErrorResponse(Exception):
    def __init__(self, status_code: int, message: Optional[str] = None):
        self.status_code = status_code
        self.message = message


class DigdirValidationErrorResponse(ErrorResponse):
    def __init__(self, response):
        errors = response.json()["errors"]

        super().__init__(
            400,
            "Validation error{} from Digdir's API:{}".format(
                "s" if len(errors) > 1 else "",
                "".join([f'\n- {e["errorMessage"]}' for e in errors]),
            ),
        )


class Message(BaseModel):
    message: Optional[str]


def error_message_models(*status_codes) -> Dict:
    return {code: {"model": Message} for code in status_codes}


def pydantic_error_to_str(err):
    # Tailor made message for the case when an invalid Maskinporten environment
    # is given.
    location = ".".join(err["loc"])

    if err["loc"] == ("path", "env"):
        return "{}: Unsupported Maskinporten environment. Must be one of: {}".format(
            location, ", ".join([e.value for e in MaskinportenEnvironment])
        )

    if err["loc"] == ("path", "client_id"):
        return f"{location}: Invalid client ID ({err['msg']})"

    if err["loc"] == ("body", "team_id"):
        return f"{location}: Invalid team ID ({err['msg']})"

    # Fall back to Pydantic's default error message in the general case.
    return f"{location}: {err['msg']}"
