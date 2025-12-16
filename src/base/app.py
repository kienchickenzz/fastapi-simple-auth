from typing import Type, Any
from typing_extensions import Annotated, Doc

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.base.middleware.global_exception import GlobalExceptionMiddleware
from src.base.exception.api.base import HTTPException
from src.base.exception.api.handler import rest_exception_handler
from src.base.endpoint.docs import router as router_docs
from src.base.endpoint.health import router as router_health
from src.base.initializer import Initializer
from src.base.config import Config

def create_fastapi_app(
    *,
    config: Annotated[
        Config,
        Doc("The configuration instance to be used by the FastAPI app."),
    ],
    initializer: Annotated[
        Type[Initializer],
        Doc("A `Lifespan` context manager handler extended from Initializer."),
    ],
    title: Annotated[
        str,
        Doc("The title of the API. It will be added to the generated OpenAPI."),
    ],
    description: Annotated[
        str,
        Doc("A description of the API (supports Markdown). It will be added to the generated OpenAPI."),
    ],
    version: Annotated[
        str,
        Doc("A version of the API (supports Markdown). It will be added to the generated OpenAPI."),
    ],
    summary: Annotated[
        str,
        Doc("A summary of the API (supports Markdown). It will be added to the generated OpenAPI."),
    ] = str(),
    team_name: Annotated[
        str,
        Doc("The name of the team who owns the service. It will be added to the generated OpenAPI."),
    ] = str(),
    team_url: Annotated[
        str,
        Doc("The URL for support questions. It will be added to the generated OpenAPI."),
    ] = str(),
    **fastapi_configs: Annotated[
        Any,
        Doc(
            """
            Any extra configurations provided by FastAPI
            (see https://fastapi.tiangolo.com/reference/fastapi/#fastapi.FastAPI).
            """
        ),
    ],
) -> FastAPI:
    """
    Returns a FastAPI instance with basic set of endpoints and middleware required by
    platform to perform logging, collect metrics and generate OpenAPI documentation.
    """
    fastapi_configs.pop("redoc_url", None)
    fastapi_configs.pop("contact", None)

    app = FastAPI(
        redoc_url=None,
        lifespan=initializer,
        title=title,
        description=description,
        version=version,
        summary=summary,
        contact={"name": team_name, "url": team_url},
        exception_handlers={HTTPException: rest_exception_handler}, # Handle business logic exceptions
        swagger_ui_parameters={
            "defaultModelsExpandDepth": -1,  # collapse/remove schemas by default in swagger UI
        },
        **fastapi_configs,
    )

    # Required endpoints
    app.include_router(router_docs, prefix="")
    app.include_router(router_health, prefix="")

    # Required middleware
    # app.add_middleware(LoggingMiddleware)  # This is the most inner middleware right before the router.
    app.add_middleware(GlobalExceptionMiddleware) # Handle unexpected exceptions
    app.add_middleware(
        CORSMiddleware,
        allow_origins=(
            config.require_list("CORS_ORIGINS", ";")
        ),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return app
