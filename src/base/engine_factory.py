from threading import Lock
from types import TracebackType
from typing import Dict, Optional, Type
from uuid import uuid4

from asyncpg import Connection # type: ignore[import]
from sqlalchemy import NullPool
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from src.base.config import Config


class EngineFactory:
    """
    Encapsulates the configurations required by data-platform to establish direct
    access to either data-platform or RDS.

    To create engines you will need the following environment variables:
        <<database_identifier>>_HOST
        <<database_identifier>>_PORT
        <<database_identifier>>_NAME
        <<database_identifier>>_USER
        <<database_identifier>>_PASSWORD

    Where <<database_identifier>> is the prefix to uniquely indentify the engine you want to create.
    This factory is already context managed by FastAPIInitializer, so it can be used straight away:

    >>> class MyInitializer(Initializer):
    ...     def __init__(self, app: FastAPI) -> None:
    ...         super().__init__(app)
    ...         self.my_repository: MyRepository
    ...
    ...     async def __aenter__(self) -> MyInitializer:
    ...         await super().__aenter__()
    ...         engine = self.engine_factory.create_engine("MY_DB")
    ...         self.my_repository = MyRepository(engine)
    ...
    ...     async def __aexit__(
    ...         self,
    ...         exc_type: Optional[Type[BaseException]],
    ...         exc_val: Optional[BaseException],
    ...         exc_tb: Optional[TracebackType]
    ...     ) -> None:
    ...          await super().__aexit__(exc_type, exc_val, exc_tb)

    This factory guarantees that only one engine will be created per repository, and you will
    be able to retrieve the engine as many times as you want.
    """

    def __init__(self, *, config: Config):
        self._config = config
        self._engine_init_lock: Lock = Lock()
        self._engines: Dict[str, AsyncEngine] = {}

    async def __aenter__(self) -> "EngineFactory":
        return self

    async def __aexit__(
        self, 
        exc_type: Optional[Type[BaseException]], 
        exc_val: Optional[BaseException], 
        exc_tb: Optional[TracebackType]
    ) -> None:
        for database_identifier, engine in self._engines.items():
            await engine.dispose()

    def create_engine(self, database_identifier: str) -> AsyncEngine:
        with self._engine_init_lock:
            if database_identifier not in self._engines:
                self._engines[database_identifier] = self._create_no_pool_engine(database_identifier.upper())

        return self._engines[database_identifier]

    def _create_no_pool_engine(self, database_identifier: str) -> AsyncEngine:
        db_host = self._config.require_config(f"{database_identifier}_HOST")
        db_port = self._config.require_config(f"{database_identifier}_PORT")
        db_name = self._config.require_config(f"{database_identifier}_NAME")
        db_user = self._config.require_config(f"{database_identifier}_USER")
        db_password = self._config.require_config(f"{database_identifier}_PASSWORD")
        url = f"postgresql+asyncpg://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

        # Data-platform configure DBs in a way that services can't have connection pools,
        # since connections are closed and returned as soon as the query is completed.
        # We should not allow any pooling nor caching in our engine otherwise we will see
        # errors in staging/production -> pgbouncer with pool_mode set to "transaction" or
        # "statement" does not support prepared statements properly.
        return create_async_engine(
            url=url,
            echo=False,
            poolclass=NullPool,
            connect_args={
                "server_settings": {"application_name": "test"},
                "statement_cache_size": 0,
                "prepared_statement_cache_size": 0,
                "connection_class": _CConnection,
            },
        )


# Necessary hack to handle data-platform no pooling configuration,
# see https://github.com/sqlalchemy/sqlalchemy/issues/6467#issuecomment-864943824
class _CConnection(Connection):
    def _get_unique_id(self, prefix: str) -> str:
        return f"__asyncpg_{prefix}_{uuid4()}__"
