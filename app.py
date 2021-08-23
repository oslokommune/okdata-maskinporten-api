import os

from fastapi import FastAPI

from resources import maskinporten_clients

root_path = os.environ.get("ROOT_PATH", "")
app = FastAPI(
    title="TODO",
    description="TODO",
    version="0.1.0",
    root_path=root_path,
)

app.include_router(maskinporten_clients.router, prefix="/clients")
