import os

from mangum import Mangum

from app import app

root_path = os.environ["ROOT_PATH"]
handler = Mangum(app=app, api_gateway_base_path=root_path)
