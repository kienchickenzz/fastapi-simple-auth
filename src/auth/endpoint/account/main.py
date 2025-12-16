from fastapi import APIRouter, Security

from src.base.dependency_injection import Injects
from src.base.exception.repository.base import NotUniqueException

# local imports
from src.auth.util.main import authenticate, get_password_hash
from src.auth.doc import Tags
from src.auth.database.repository.account import AccountRepository
from src.auth.database.repository.jwt_token import JWTRepository
from src.auth.dto.account import AccountRequest, AccountResponse
from src.auth.exception.api.account_exception import AnalyzerException, AccountBadRequestException, AccountEmailRegistered, AccountNotFoundException, AccountUnAuthorizedException

router = APIRouter(tags=[Tags.ACCOUNT], prefix="/v1/account")


@router.post(
    path="/",
    summary="Add account",
    description="Create new account",
    status_code=200,
    responses={
        400: {"model": AccountBadRequestException.model},
        500: {"model": AnalyzerException.model},
    },
)
async def add_account(
    request: AccountRequest,
    account_repository: AccountRepository = Injects("account_repository"),
) -> AccountResponse:
    pass_hash = get_password_hash(request.password)
    try:
        account_entity = await account_repository.create(
            values={
                "organization_name": request.organization_name,
                "email": request.email,
                "phone": request.phone,
                "hashed_password": pass_hash,
            }
        )
    except NotUniqueException:
        raise AccountEmailRegistered()

    return AccountResponse(
        id=account_entity.id,
        organization_name=account_entity.organization_name,
        email=account_entity.email,
        phone=account_entity.phone
    )


@router.get(
    path="/",
    summary="Get account",
    description="Get account info",
    status_code=200,
    responses={
        404: {"model": AccountNotFoundException.model},
        401: {"model": AccountUnAuthorizedException.model},
        500: {"model": AnalyzerException.model},
    },
)
async def get_account(
    account_id: int = Security(authenticate),
    account_repository: AccountRepository = Injects("account_repository"),
) -> AccountResponse:
    account_entity = await account_repository.get_one(entity_id=account_id)

    return AccountResponse(
        id=account_entity.id,
        organization_name=account_entity.organization_name,
        email=account_entity.email,
        phone=account_entity.phone
    )


@router.patch(
    path="/",
    summary="Update account",
    description="Update account data",
    status_code=200,
    responses={
        400: {"model": AccountBadRequestException.model},
        401: {"model": AccountUnAuthorizedException.model},
        404: {"model": AccountNotFoundException.model},
        500: {"model": AnalyzerException.model},
    },
)
async def update_account(
    request: AccountRequest,
    account_id: int = Security(authenticate),
    account_repository: AccountRepository = Injects("account_repository"),
) -> AccountResponse:
    account_entity = await account_repository.update(
        entity_id=account_id,
        values={
            "organization_name": request.organization_name,
            "email": request.email,
            "phone": request.phone,
        }
    )

    return AccountResponse(
        id=account_entity.id,
        organization_name=account_entity.organization_name,
        email=account_entity.email,
        phone=account_entity.phone
    )


@router.delete(
    path="/",
    summary="Delete account",
    description="Delete account and related data (configs, files, etc.)",
    status_code=204,
    responses={
        401: {"model": AccountUnAuthorizedException.model},
        404: {"model": AccountNotFoundException.model},
        500: {"model": AnalyzerException.model},
    },
)
async def delete_account(
    account_id: int = Security(authenticate),
    account_repository: AccountRepository = Injects("account_repository"),
    jwt_repository: JWTRepository = Injects("jwt_repository"),
) -> None:
    # Delete keys and invalidate access
    await jwt_repository.delete_by_account_id(account_id=account_id)
    
    # Delete the actual user entity
    return await account_repository.delete(entity_id=account_id)
