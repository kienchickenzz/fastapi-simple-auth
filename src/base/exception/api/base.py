from http import HTTPStatus
from typing import Any, Dict, Type

from pydantic import BaseModel
from starlette.responses import JSONResponse


class RestException(BaseModel):
    """
    This model represents the generic payload that is used by FastAPI. It is assigned to
    all exceptions that extend HTTPException by default.

    This is meant to return human-readable error messages, but it is not recommended for
    machine processing. Read HTTPException documentation to understand how to customize
    the exception payload.
    """

    detail: str = "<failure-description>"


class HTTPException(Exception):
    """
    Parent exception for webserver package. Vanilla implementations are available for
    the most common error codes.

    Classes that inherit from HTTPException will have a generic string `detail` field
    exposed to clients in Swagger. This field is only reliable for human-readable messages,
    not for machine processing.

    To customize the exception payload, follow the example below:

    >>> class MyCustomPayload(BaseModel):
    ...     field_1: str
    ...     field_2: int = 1010
    ...
    ... class MyCustomException(HTTPException):
    ...     status = HTTPStatus.IM_A_TEAPOT
    ...     model = MyCustomPayload

    Once model and exception are defined you can raise it as usual in your code:

    >>>  raise MyCustomException(field_1="My custom field")
    ...  raise MyCustomException(field_1="First field", field_2=25)

    Your custom exception will be correctly exported to OpenAPI, Swagger and client code.


    Why does it look ugly and painful??
    It is a combination of two factors:
        1. Pydantic can't be applied in exceptions without dataclasses,
            see https://github.com/pydantic/pydantic/discussions/5770
        2. FastAPI only adds Pydantic models (not plain exceptions) to the OpenAPI
            schema definitions, which breaks our code generation tool for clients.

    We tried to achieve the cleanest approach possible to stitch up the lacking
    features together with the least amount of manual work possible.

    We will keep an eye on FastAPI and Pydantic updates to understand if we can
    improve the solution and unify all information in one object only.
    """

    status: HTTPStatus
    model: Type[BaseModel] = RestException
    payload: BaseModel

    def __init__(self, **payload_args: Any):
        assert hasattr(self, "status"), "http_status_not_defined"
        self.payload: BaseModel = self.model(**payload_args)

    def get_body(self) -> JSONResponse:
        """
        Converts the exception into a JSONResponse that matches `model` definition.

        :return: JSONResponse with the exception payload that will be returned to the client.
        """
        return JSONResponse(self.payload.dict(), status_code=self.status, headers=None)

    @classmethod
    def get_description(cls) -> Dict[int, Any]:
        """
        Exposes the exception in Swagger through OpenAPI definitions.
        See https://fastapi.tiangolo.com/advanced/additional-responses/

        :return: dictionary with the Pydantic model that describes the HTTPException.
        """
        return {cls.status.value: {"model": cls.model}}
