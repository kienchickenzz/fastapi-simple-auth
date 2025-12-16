from typing import Optional
from pydantic import Field

from src.base.dto.main import RequestBase, ResponseBase


class AccountRequest(RequestBase):
    organization_name: Optional[str] = Field(title="Organization name", default="Test org")
    email: str = Field(title="Email", description="Account email (must be unique)", default="test_user@email.eu")
    password: str = Field(title="Password", description="Account password", default="test_user")
    phone: Optional[str] = Field(title="Phone number", description="Account phone number (optional)", default="+372568966")


class AccountResponse(ResponseBase):
    id: int = Field(title="Account ID", description="Unique identifier for account", exclude=True)
    organization_name: Optional[str] = Field(title="Organization name", default="Test org")
    email: str = Field(title="Email", description="Account email (must be unique)", default="test_user@email.eu")
    phone: Optional[str] = Field(title="Phone number", description="Account phone number (optional)", default="+372568966")
