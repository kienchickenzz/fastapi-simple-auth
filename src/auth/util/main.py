from uuid import UUID
from os import environ
from datetime import datetime, timedelta, timezone

from jwt import encode, decode
from jwt.exceptions import InvalidTokenError
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

from src.base.dependency_injection import Injects
from src.base.exception.repository.base import NotFoundException

# Local imports
from src.auth.database.repository.jwt_token import JWTRepository
from src.auth.exception.api.account_exception import AccountUnAuthorizedException

ACCESS_SECRET_KEY = environ.get("ACCESS_SECRET_KEY")
REFRESH_SECRET_KEY = environ.get("REFRESH_SECRET_KEY")
ALGORITHM = environ.get("ALGORITHM")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/account/authentication/generate_token", refreshUrl="/v1/account/authentication/refresh_token", auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def authenticate(
    token: str = Depends(oauth2_scheme),
    jwt_repository: JWTRepository = Injects("jwt_repository"),
) -> UUID:
    if token:
        # check that token has not been invalidated (removed from repository)
        try:
            await jwt_repository.get_by_token_value(token_value=token)
        except NotFoundException:
            raise AccountUnAuthorizedException()
        
        return verify_token(token=token)
    
    # If no authentication method hit then un-authorized
    raise AccountUnAuthorizedException()


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def password_hash_match(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:  # default expiry is 30 minutes
        expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = encode(to_encode, ACCESS_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: timedelta | None = None):
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
    encoded_jwt = encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(
    token: str,
    type: str = "access"
) -> int:
    try:
        if type == "access":
            secret_key = ACCESS_SECRET_KEY
        else:
            secret_key = REFRESH_SECRET_KEY

        payload: dict = decode(token, secret_key, algorithms=[ALGORITHM])
        account_id = payload.get("sub")
        if account_id is None:
            raise AccountUnAuthorizedException()
    except InvalidTokenError:
        raise AccountUnAuthorizedException()

    return int(account_id)
