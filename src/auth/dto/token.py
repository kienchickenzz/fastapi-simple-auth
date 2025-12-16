from pydantic import Field

from src.base.dto.main import RequestBase, ResponseBase


class AccessTokenResponse(ResponseBase):
    access_token: str = Field(
        title="Access token",
        description="Access token value",
        examples=[
            "afJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ91eyJzdWIiOiIzZWJmMzFmNS1jODRiLTRkY2QtOTM5NS01"
            "MjYyYzQyNjI0MzMiLCJleHAiOj77NTkzNzk0Nzd9.Ci4C90Rkc_zbPJxGn9AaMM7jgybPZN9e75IiriZOLMs"
        ],
        alias="access_token"
    )
    refresh_token: str = Field(
        title="Refresh token",
        description="Refresh token value",
        examples=[
            "e7JhbGciOiJIUzI1NiIsInR5cCI6IkpXVsui1eyJzdWIiOiIzZWJmMzFmNS1jODRiLTRkY2QtOTM5NS01"
            "MjYyYzQyNjI0MzMiLCJleHAiOj77NTkzNzk0Nzd9.Ci4C90Rkc_zbPJxGn9AaMM7jgybPZN9e75IiriZOLMs"
        ],
        alias="refresh_token"
    )
    token_type: str = Field(title="Token type", description="Access token type", default="bearer", alias="token_type")


class RefreshTokenRequest(RequestBase):
    refresh_token: str = Field(title="Refresh token", alias="refresh_token")
