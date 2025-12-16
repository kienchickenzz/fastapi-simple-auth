from sqlalchemy.orm import Mapped, mapped_column

from src.base.database.model.base import Base


class Account(Base):
    __tablename__ = "account"
    
    email: Mapped[str] = mapped_column(
        "email", nullable=False, unique=True
    )
    organization_name: Mapped[str] = mapped_column(
        "organization_name", nullable=True
    )
    phone: Mapped[str] = mapped_column(
        "phone", nullable=True
    )
    hashed_password: Mapped[str] = mapped_column(
        "hashed_password", nullable=False
    )

    def __repr__(self) -> str:
        return f"Account(organization_name={self.organization_name},email={self.email},phone={self.phone})"
