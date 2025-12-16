from typing import Any, Type, Union

from starlette.requests import Request
from starlette.responses import Response

from src.base.exception.api.base import HTTPException


async def rest_exception_handler(_: Request, exc: HTTPException) -> Response:
    return exc.get_body()


def compose_exceptions(*exceptions: Type[HTTPException]) -> dict[Union[int, str], dict[str, Any]]:
    """
    Use this method to document the exceptions thrown by your APIRouter, for example:

    >>> @router.post(
    ...     "/v1/my-object",
    ...     response_model=MyObject,
    ...     responses=compose_exceptions(HTTPBadRequestException, HTTPForbiddenException, MyCustomException)
    ... )

    :param exceptions: list of exception that extend from HTTPException
    :return: dictionary description of exceptions according to FastAPI standards
    """
    responses: dict = {}

    for exception in exceptions:
        responses.update(exception.get_description())

    return responses
