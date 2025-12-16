from pydantic import Field

from src.base.dto.main import RequestBase, ResponseBase


class AccessTokenResponse(ResponseBase):
    access_token: str = Field(
        title="Access token",
        description="Access token value",
        alias="access_token"
    )
    refresh_token: str = Field(
        title="Refresh token",
        description="Refresh token value",
        alias="refresh_token"
    )


class RefreshTokenRequest(RequestBase):
    refresh_token: str = Field(title="Refresh token", alias="refresh_token")
