from abc import ABC
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional, Sequence, Type, TypeVar, Generic, Union, cast

from pydantic.alias_generators import to_snake

from sqlalchemy import insert, select, update, func, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.engine import Result, RowMapping, CursorResult

from src.base.database.model.base import Base
from src.base.exception.repository.base import NotFoundException

T = TypeVar("T", bound=Base)

# TODO: Triển khai phương thức execute custom SQL query
class Repository(ABC, Generic[T]):
    """
    Abstract repository that provides ready-to-be-used get, create and update operations to
    SQLAlchemy models.

    Delete method is not provided by default because we encourage immutability, so this
    operation must be implemented by subclasses whenever applicable.
    """

    def __init__(self, engine: AsyncEngine, db_model: Type[T]):
        self._model = db_model
        self._entity_label: str = to_snake(db_model.__name__)
        self._engine: AsyncEngine = engine
        self._session_factory = async_sessionmaker(bind=self._engine, autocommit=False, autoflush=False)

    @asynccontextmanager
    async def _get_session(self, **kw: Any) -> AsyncIterator[AsyncSession]:
        session = self._session_factory(**kw)
        try:
            yield session
        finally:
            await session.close()

    async def get_all(self) -> Sequence[T]:
        """
        Fetch all entities from the database. Method uses generic type T which will be made specific
        when specific repository is implemented.

        :return: List of entities (rows)
        :rtype: Sequence[T]
        """
        async with self._get_session() as session:
            query = select(self._model)
            scalars = await session.scalars(query)
            result = scalars.all()

        return result

    async def get_one(self, entity_id: int) -> T:
        """
        Fetch single entity from database. Method uses generic type T which will be made specific
        when specific repository is implemented.

        :param entity_id: Entity int to filter with
        :type entity_id: int
        :raises NotFoundException: If entity with specified int does not exist
        :return: Entity (row)
        :rtype: T
        """
        async with self._get_session() as session:
            query = select(self._model).where(self._model.id == entity_id)
            scalars = await session.scalars(query)
            result: Optional[T] = scalars.first()
            
            if result is None:
                raise NotFoundException(key_name="int", table_name=self._model.__tablename__, entity_id=entity_id)

        return result
    

    async def get_multiple(self, skip: Optional[int] = 0, limit: Optional[int] = 20) -> tuple[Sequence[T], int]:
        """
        Fetch paginated entities with total count. Method uses generic type T
        which will be made specific when specific repository is implemented.

        :param skip: Number of records to skip
        :type skip: int
        :param limit: Maximum number of records to return
        :type limit: Optional[int]
        :return: Tuple of (records, total_count)
        :rtype: tuple[Sequence[T], int]
        """
        async with self._get_session() as session:
            # Count total records
            count_query = select(func.count()).select_from(self._model)
            total = (await session.scalar(count_query)) or 0

            # Select records with pagination
            query = select(self._model)

            # Apply pagination
            if skip:
                query = query.offset(skip)
            if limit:
                query = query.limit(limit)

            scalars = await session.scalars(query)
            result = scalars.all()

        return result, total

    async def create(self, values: dict[str, Any]) -> T:
        """
        Insert a new entity into database. Method uses generic type T which will be made specific
        when specific repository is implemented.

        :param values: Entity fields mapping
        :type values: dict[str, Any]
        :return: Inserted entity
        :rtype: T
        """
        async with self._get_session() as session:
            query = insert(self._model).values(values).returning(self._model.id)
            result: Optional[int]

            try:
                result = await session.scalar(query)
                await session.commit()
            except IntegrityError as error:
                self._parse_sql_error(error)
        
        if result is None:
            raise ValueError("Insert failed, no ID returned")
        
        return await self.get_one(result)

    async def update(self, entity_id: int, values: dict[str, Any]) -> T:
        """
        Update an entity in the database. Method uses generic type T which will be made specific
        when specific repository is implemented.

        :param entity_id: UUID of the entity to be updated
        :type entity_id: UUID
        :param values: Entity fields mapping that will be updated
        :type values: dict[str, Any]
        :return: Updated entity
        :rtype: T
        """
        async with self._get_session() as session:
            values = {**values}
            query = update(self._model).where(self._model.id == entity_id).values(values).returning(self._model.id)

            try:
                result = await session.scalar(query)
                await session.commit()
            except IntegrityError as error:
                self._parse_sql_error(error)

        return await self.get_one(result) # type: ignore
    
    async def execute_sql(
        self,
        sql: str,
        parameters: Optional[dict[str, Any]] = None,
        fetch: bool =True,
    ) -> Union[Sequence[RowMapping], int]:
        """
        Execute custom SQL query.
        
        :param sql: Raw SQL query string
        :param parameters: Query parameters (prevents SQL injection)
        :param fetch: If True, fetch results. If False, execute without fetching (for INSERT/UPDATE/DELETE)
        :return: Results based on parameters
        """
        async with self._get_session() as session:
            try:
                query = text(sql)
                
                if parameters:
                    result = await session.execute(query, parameters)
                else:
                    result = await session.execute(query)

                if not fetch:
                    await session.commit()
                    cursor_result = cast(CursorResult, result)
                    return cursor_result.rowcount

                return result.mappings().all()
                
            except IntegrityError as error:
                await session.rollback()
                self._parse_sql_error(error)

        # This line should never be reached
        raise RuntimeError("Unexpected execution flow")

    def _parse_sql_error(self, exc: IntegrityError) -> None:
        code = str(getattr(exc.orig, "pgcode", ""))
        message = str(getattr(exc.orig, "args", ""))
        self.handle_sql_error(code, message, exc)

    def handle_sql_error(self, error_code: str, error_message: str, exc: Exception) -> None:
        """
        Must handle error scenarios raised by the database, due to violation of foreign keys,
        unique keys, required column values and so on.

        Refer to https://www.postgresql.org/docs/current/errcodes-appendix.html for more
        details on codes and messages.

        :param error_code: code provided by Postgres
        :param error_message: message provided by Postgres
        :param exc: original exception raised by the ORM engine
        """
        raise NotImplementedError()
