from http import HTTPStatus

from src.base.exception.api.base import HTTPException


class AnalyzerException(HTTPException):
    status = HTTPStatus.INTERNAL_SERVER_ERROR
