from http import HTTPStatus
from typing import Any

# local imports
from src.auth.exception.api.analyzer_base_exception import AnalyzerException


# base exception to group and catch all account endpoint bad request related exceptions
class AccountBadRequestException(AnalyzerException):
    status = HTTPStatus.BAD_REQUEST

    def __init__(self, detail: Any = "account_endpoint_bad_request"):
        super().__init__(detail=detail)

class AccountEmailRegistered(AccountBadRequestException):
    status = HTTPStatus.BAD_REQUEST

    def __init__(self, detail: Any = "account_email_already_registered"):
        super().__init__(detail=detail)


# base exception to group and catch all account endpoint not found related exceptions
class AccountNotFoundException(AnalyzerException):
    status = HTTPStatus.NOT_FOUND

    def __init__(self, detail: Any = "account_endpoint_entity_not_found"):
        super().__init__(detail=detail)



# base exception to group and catch all account endpoint unauthorized related exceptions
class AccountUnAuthorizedException(AnalyzerException):
    status = HTTPStatus.UNAUTHORIZED

    def __init__(self, detail: Any = "account_endpoint_unauthorized"):
        super().__init__(detail=detail)