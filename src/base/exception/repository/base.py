from typing import Union

# Base exception to group and catch all repository related exceptions
class RepositoryException(Exception):
    pass


class NotFoundException(RepositoryException):
    
    def __init__(self, entity_id: Union[int, str], key_name: str, table_name: str):
        super().__init__()
        self.entity_id = entity_id
        self.key_name = key_name
        self.table_name = table_name


class NotUniqueException(RepositoryException):
    pass


class RestrictionException(RepositoryException):
    pass
