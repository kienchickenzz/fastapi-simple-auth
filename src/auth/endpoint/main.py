from fastapi import APIRouter

from src.auth.endpoint.account.main import router as router_account
from src.auth.endpoint.token.main import router as router_token

main_router = APIRouter(prefix="/api")
main_router.include_router(router_account)
main_router.include_router(router_token)
