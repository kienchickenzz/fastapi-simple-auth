from uuid import UUID

from sqlalchemy.orm import Mapped, mapped_column

from src.base.database.model.base import Base


class JWTToken(Base):
    __tablename__ = "jwt_token"

    account_id: Mapped[UUID] = mapped_column(
        "account_uuid", nullable=False
    )
    access_token: Mapped[str] = mapped_column(
        "last_name", nullable=False
    )
    refresh_token: Mapped[str] = mapped_column(
        "email", nullable=False
    )

    def __repr__(self) -> str:
        return f"JWTToken(account_id={self.account_id},access_token={self.access_token},refresh_token={self.refresh_token})"
