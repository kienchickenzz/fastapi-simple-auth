from types import TracebackType
from typing import Optional, Type

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine
from src.base.initializer import State, Initializer

# local imports
from src.auth.database.repository.account import AccountRepository
from src.auth.database.repository.jwt_token import JWTRepository


class ServiceState(State):
    # repositories
    db_engine: AsyncEngine
    account_repository: AccountRepository
    jwt_repository: JWTRepository
    # utilities
    

class AuthServiceInitializer(Initializer):
    def __init__(self, app: FastAPI) -> None:
        super().__init__(app=app)

    async def __aenter__(self) -> ServiceState:
        state = await super().__aenter__()

        # Initialize DB engine
        db_engine = self.engine_factory.create_engine("DB")

        # Initialize utilities

        # Initialize repositories
        account_repository = AccountRepository(engine=db_engine)
        jwt_repository = JWTRepository(engine=db_engine)

        # Initialize services/tools
        
        return ServiceState(
            **state,
            db_engine=db_engine,
            account_repository=account_repository,
            jwt_repository=jwt_repository,
        )

    async def __aexit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> None:
        await super().__aexit__(exc_type, exc_val, exc_tb)
