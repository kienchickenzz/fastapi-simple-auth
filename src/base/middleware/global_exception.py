import traceback
from http import HTTPStatus

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class GlobalExceptionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        
        except ValueError as err:
            traceback.print_exception(type(err), err, err.__traceback__)
            return JSONResponse(
                status_code=HTTPStatus.BAD_REQUEST.value,
                content={"errors": [HTTPStatus.BAD_REQUEST.phrase]},
            )
        
        except Exception as err:
            traceback.print_exception(type(err), err, err.__traceback__)
            return JSONResponse(
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR.value,
                content={"errors": [HTTPStatus.INTERNAL_SERVER_ERROR.phrase]},
            )
