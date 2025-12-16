import re
from typing import Type

from sqlalchemy.ext.asyncio import AsyncEngine

from src.base.exception.api.base import HTTPException
from src.base.database.repository.base import Repository, T

# local imports
from src.base.exception.repository.base import NotUniqueException, NotFoundException, RestrictionException

_UNIQUE_KEY_VIOLATION = r".*duplicate key value violates unique constraint \"(.*)\".*"
_FOREIGN_KEY_VIOLATION = r".*insert or update on table .* violates foreign key constraint .* Key \((.*)\)=\((.*)\) is not present in table \"(.*)\".*"  # pylint: disable=line-too-long
_RESTRICT_VIOLATION = r".*update or delete on table .* violates foreign key constraint .* Key .*=\((.*)\) is still referenced from table \"(.*)\".*"  # pylint: disable=line-too-long


class BaseRepository(Repository[T]):
    def __init__(self, engine: AsyncEngine, db_model: Type[T]):
        super().__init__(engine, db_model)
        self._entity_name: str = self._pascal_to_human(db_model.__name__).replace(" table", "")
        self.index_to_exception: dict[str, HTTPException] = {}

    def _pascal_to_human(self, string: str) -> str:
        words = re.split("(?<=.)(?=[A-Z])", string)
        return words[0].capitalize() + "".join(" " + word.lower() for word in words[1:])

    def _snake_to_human(self, string: str) -> str:
        words = string.split("_")
        return words[0].capitalize() + "".join(" " + word for word in words[1:])
    
    def _extract_violated_index_name(self, db_message: str) -> str:
        match = re.match(_UNIQUE_KEY_VIOLATION, db_message)
        if match:
            return match.group(1)

        return ""

    def handle_sql_error(self, error_code: str, error_message: str, exc: Exception) -> None:
        if error_code == "23505":  # UNIQUE CONSTRAINT VIOLATION
            violated_index_name = self._extract_violated_index_name(error_message)

            custom_exception = self.index_to_exception.get(violated_index_name)

            if custom_exception:
                raise custom_exception from exc

            raise NotUniqueException()

        if error_code == "23503":  # FOREIGN KEY VIOLATION
            match = re.match(_FOREIGN_KEY_VIOLATION, error_message)
            if match:
                key_name = match.group(1).removesuffix("_uuid")
                entity_id = match.group(2)
                table_name = match.group(3)

                raise NotFoundException(key_name=key_name, entity_id=entity_id, table_name=table_name)

            match = re.match(_RESTRICT_VIOLATION, error_message)
            if match:
                entity_id = match.group(1).removesuffix("_uuid")
                table = match.group(2)

                raise RestrictionException()

            if not match:
                raise exc

        raise exc
