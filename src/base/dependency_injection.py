from typing import Any

from fastapi import Request, params
from starlette import datastructures
from typing_extensions import Annotated, Doc


def Injects(  # noqa: N802
    dependency: Annotated[
        str,
        Doc("The name of dependency, defined in State, that will be injected in the router."),
    ],
    *,
    use_cache: Annotated[
        bool,
        Doc(
            """
                By default, after a dependency is called the first time in a request, if
                the dependency is declared again for the rest of the request (for example
                if the dependency is needed by several dependencies), the value will be
                re-used for the rest of the request.

                Set `use_cache` to `False` to disable this behavior and ensure the
                dependency is called again (if declared more than once) in the same request.
                """
        ),
    ] = True,
) -> Any:
    def _inject_from_state(request: Request) -> Any:
        return getattr(request.state, dependency)

    return params.Depends(dependency=_inject_from_state, use_cache=use_cache)


def InjectState(  # noqa: N802
    *,
    use_cache: Annotated[
        bool,
        Doc(
            """
                By default, after a dependency is called the first time in a request, if
                the dependency is declared again for the rest of the request (for example
                if the dependency is needed by several dependencies), the value will be
                re-used for the rest of the request.

                Set `use_cache` to `False` to disable this behavior and ensure the
                dependency is called again (if declared more than once) in the same request.
                """
        ),
    ] = True,
) -> Any:
    def _inject_state(request: Request) -> datastructures.State:
        return request.state

    return params.Depends(dependency=_inject_state, use_cache=use_cache)
