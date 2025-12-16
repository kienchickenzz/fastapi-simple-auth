from pydantic import BaseModel, Field, ConfigDict, field_validator
from humps import camelize
from fastapi import Query

class RequestBase(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        alias_generator=camelize,
        populate_by_name=True,
        validate_assignment=True,
        extra='forbid',
    )

class PaginatedRequestBase(RequestBase):
    model_config = ConfigDict(
        frozen=True,
        alias_generator=camelize,
        populate_by_name=True,
        validate_assignment=True,
        extra='forbid',
    )

    target_page: int = Field(
        default=1,
        ge=1, # Greater than or equal to 1
        description="Target page number"
    )
    page_size: int = Field(
        default=10,
        ge=1,
        le=100, # Limit tối đa
        description="Number of items per page"
    )

    # Custom validator
    @field_validator('page_size')
    @classmethod
    def validate_page_size(cls, v):
        if v > 100:
            raise ValueError("Page size cannot exceed 100")
        return v

    @classmethod
    def as_query(
        cls,
        target_page: int = Query(
            default=1, 
            alias="targetPage", 
            ge=1,
            description="Target page number"
        ),
        page_size: int = Query(
            default=10, 
            alias="pageSize", 
            ge=1,
            le=100,
            description="Number of items per page"
        )
    ) -> "PaginatedRequestBase":
        return cls(target_page=target_page, page_size=page_size)

class ResponseBase(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        alias_generator=camelize,
        populate_by_name=True,
        validate_assignment=True,
        extra='ignore',
        from_attributes=True
    )

class PaginatedResponseBase(ResponseBase):
    current_page: int
    total_pages: int
    page_size: int
