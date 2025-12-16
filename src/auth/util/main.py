from datetime import datetime, timedelta, timezone
from typing import Optional

from jwt import encode, decode
from jwt.exceptions import InvalidTokenError
from fastapi import Depends
from fastapi.security import (
    OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
)
from passlib.context import CryptContext

from src.base.config import Config
from src.base.dependency_injection import Injects
from src.base.exception.repository.base import NotFoundException

# Local imports
from src.auth.database.repository.jwt_token import JWTRepository
from src.auth.exception.api.account_exception import AccountUnAuthorizedException

http_bearer_scheme = HTTPBearer(auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="api/v1/account/authentication/generate_token",
    refreshUrl="api/v1/account/authentication/refresh_token",
    auto_error=False
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def authenticate(
    # Token xác thực sau sẽ ghi đè lên token trước nếu cả hai cùng được cung cấp 
    oauth_token: Optional[str] = Depends(oauth2_scheme),
    http_credential: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer_scheme),
    jwt_repository: JWTRepository = Injects("jwt_repository"),
    config: Config = Injects("config")
) -> int:
    
    token = None

    # Ưu tiên HTTP Bearer token
    if http_credential:
        token = http_credential.credentials
    elif oauth_token:
        token = oauth_token

    if token:
        # check that token has not been invalidated (removed from repository)
        try:
            await jwt_repository.get_by_token_value(token_value=token)
        except NotFoundException:
            raise AccountUnAuthorizedException()
        
        return verify_token(token=token, config=config)
    
    # If no authentication method hit then un-authorized
    raise AccountUnAuthorizedException()


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def password_hash_match(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    data: dict, 
    config: Config,
    expires_delta: timedelta | None = None,
) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:  # default expiry is 30 minutes
        expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = encode(
        to_encode, 
        config.require_config("ACCESS_SECRET_KEY"), 
        algorithm=config.require_config("ALGORITHM")
    )
    return encoded_jwt


def create_refresh_token(
    data: dict, 
    config: Config,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a refresh token
    Args:
        data (dict): data to be encoded
        expires_delta (timedelta | None, optional): expiration time. Defaults to None.
    Returns:
        str: JWT token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:  # default expiry is 60 minutes
        expire = datetime.now(timezone.utc) + timedelta(minutes=60)  # FIXME: expiry must be longer here because we don't generate new refresh tokens - this single token will be used to refresh access token until it expiry in whcih case we force the user to login again
    to_encode.update({"exp": expire})
    encoded_jwt = encode(
        to_encode, 
        config.require_config("REFRESH_SECRET_KEY"), 
        algorithm=config.require_config("ALGORITHM")
    )
    return encoded_jwt


def verify_token(
    token: str,
    config: Config,
    type: str = "access",
) -> int:
    try:
        if type == "access":
            secret_key = config.require_config("ACCESS_SECRET_KEY")
        else:
            secret_key = config.require_config("REFRESH_SECRET_KEY")

        payload: dict = decode(token, secret_key, algorithms=[config.require_config("ALGORITHM")])
        account_id = payload.get("sub")
        if account_id is None:
            raise AccountUnAuthorizedException()
    except InvalidTokenError:
        raise AccountUnAuthorizedException()

    return int(account_id)
