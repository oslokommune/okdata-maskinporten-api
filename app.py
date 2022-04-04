import os

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from okdata.aws.logging import add_fastapi_logging

from resources import maskinporten_clients
from resources.errors import ErrorResponse, pydantic_error_to_str

root_path = os.environ.get("ROOT_PATH", "")
app = FastAPI(
    title="TODO",
    description="TODO",
    version="0.1.0",
    root_path=root_path,
)

add_fastapi_logging(app)

app.include_router(maskinporten_clients.router, prefix="/clients")


@app.exception_handler(ErrorResponse)
def abort_exception_handler(request: Request, exc: ErrorResponse):
    return JSONResponse(status_code=exc.status_code, content={"message": exc.message})


@app.exception_handler(RequestValidationError)
def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "message": "\n\n".join(map(pydantic_error_to_str, exc.errors())),
        },
    )
