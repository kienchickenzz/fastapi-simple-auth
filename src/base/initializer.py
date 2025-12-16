from types import TracebackType
from typing import Optional, Type, Mapping, Any

from fastapi import FastAPI

from src.base.middleware.global_exception import GlobalExceptionMiddleware
from src.base.config import Config
from src.base.engine_factory import EngineFactory


class State(Mapping):
    """
    Contains all the dependencies that can be injected in Routers.
    Can be extended by your application to expose more injectable objects.
    """

    config: Config
    
    def __init__(self, /, **kwargs: Any):
        self.__dict__.update(kwargs)

    def __getitem__(self, item):
        return self.__dict__[item]

    def __iter__(self):
        return self.__dict__.__iter__()

    def __len__(self):
        return self.__dict__.__len__()


class Initializer:

    _DOCS_ENDPOINT = "/"
    _HEALTH_ENDPOINT = "/health"
    _OPENAPI_VERSION = "3.0.2"

    def __init__(self, app: FastAPI, config: Optional[Config] = None) -> None:
        self.config: Config = config if config else Config()
        self._app = app
        self.engine_factory = EngineFactory(config=self.config)

    async def __aenter__(self) -> State:
        state = State(
            config=self.config,
        )

        # FastAPI setup and validation
        self._setup_app()
        self._validate_openapi()
        self._validate_endpoints()
        self._validate_middleware()

        # Database setup
        await self.engine_factory.__aenter__()

        # self.logger.info("service_initialized")

        return state

    async def __aexit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> None:
        # self.logger.info("service_shutting_down")
        await self.engine_factory.__aexit__(exc_type, exc_val, exc_tb)
    
    def _setup_app(self) -> None:
        self._app.version = self.config.get_config("RELEASE", "")
        self._app.debug = self.config.get_bool("DEBUG", False)

    def _validate_openapi(self) -> None:
        spec = self._app.openapi()

        assert "info" in spec, "openapi_spec_info_missing"
        assert "title" in spec["info"], "openapi_spec_title_missing"
        assert "description" in spec["info"], "openapi_spec_description_missing"
        assert "contact" in spec["info"], "openapi_spec_contact_missing"
        assert "name" in spec["info"]["contact"], "openapi_spec_contact_name_missing"
        assert "url" in spec["info"]["contact"], "openapi_spec_contact_url_missing"

        assert "FastAPI" != spec["info"]["title"], "openapi_spec_title_missing"
        # assert spec["info"]["contact"]["url"].startswith(""), "openapi_spec_url_invalid_host"

        if spec["openapi"] != self._OPENAPI_VERSION:
            # self.logger.warning(
            #     "openapi_version_overwritten",
            #     original_version=spec["openapi"],
            #     supported_versions=self._OPENAPI_VERSION,
            # )
            spec["openapi"] = self._OPENAPI_VERSION

    def _validate_endpoints(self) -> None:
        endpoints = [route.path for route in self._app.routes]
        assert self._HEALTH_ENDPOINT in endpoints, "health_endpoint_missing"
        assert self._DOCS_ENDPOINT in endpoints, "docs_endpoint_missing"

    def _validate_middleware(self) -> None:
        middlewares = [middleware.cls for middleware in self._app.user_middleware]
        assert GlobalExceptionMiddleware in middlewares, "global_exception_middleware_missing"
