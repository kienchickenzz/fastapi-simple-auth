from os import environ

from dotenv import load_dotenv

from src.base.app import create_fastapi_app
from src.base.config import Config

from src.auth.auth_service_initializer import AuthServiceInitializer
from src.auth.endpoint.main import main_router as router_auth
from src.auth.doc import Tags

load_dotenv('.env')
config = Config(environ)

app = create_fastapi_app(
    config=config,
    initializer=AuthServiceInitializer,
    title="Simple Auth Service",
    description="Simple authentication service",
    version="0.1.0",
    team_name="core",
    team_url="https://invalid-address.ee",
    openapi_tags=Tags.get_docs(),
)

# Service routes
app.include_router(router_auth)
