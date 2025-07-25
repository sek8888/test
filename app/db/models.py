from datetime import date, datetime
import uuid
from enum import Enum
from sqlalchemy import (
    ForeignKey,
    String,
    Integer,
    DateTime,
    Boolean,
    Date,
    Enum as SQLEnum,
    text,
    UUID
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from typing import Optional


class Base(DeclarativeBase):
    pass


class UserRole(Enum):
    PATIENT = "patient"
    DOCTOR = "doctor"
    ORGANIZATION = "organization"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    access_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        unique=True,
        index=True,
        nullable=False,
        server_default=text("gen_random_uuid()")
    )
    integration_id: Mapped[Optional[int]] = mapped_column(unique=True)
    role: Mapped[UserRole] = mapped_column(SQLEnum(UserRole), nullable=False)

    email: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    password: Mapped[Optional[str]] = mapped_column(String(255))

    name: Mapped[Optional[str]] = mapped_column(String(255))
    surname: Mapped[Optional[str]] = mapped_column(String(255))
    patronymic: Mapped[Optional[str]] = mapped_column(String(255))
    dob: Mapped[Optional[date]] = mapped_column(Date)

    # token: Mapped[Optional[str]] = mapped_column(String(255))
    # otp_exp: Mapped[Optional[datetime]] = mapped_column(DateTime)
    # otp_token: Mapped[Optional[str]] = mapped_column(String(255))
    # forget_exp: Mapped[Optional[datetime]] = mapped_column(DateTime)
    # forget_token: Mapped[Optional[str]] = mapped_column(String(255))

    verified: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false")
    )
    modified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=text("CURRENT_TIMESTAMP"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )

    # Relationships
    doctor_orders: Mapped[list["Order"]] = relationship(
        back_populates="doctor", foreign_keys="Order.doctor_id"
    )
    patient_orders: Mapped[list["Order"]] = relationship(
        back_populates="patient", foreign_keys="Order.user_id"
    )


class Order(Base):
    __tablename__ = "orders"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    integration_id: Mapped[Optional[str]] = mapped_column(
        String(255), unique=True
    )
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"))
    doctor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"))

    number: Mapped[Optional[str]] = mapped_column(String(255))
    blank_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    created_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )

    modified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=text("CURRENT_TIMESTAMP"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )

    # Relationships
    patient: Mapped[Optional["User"]] = relationship(
        back_populates="patient_orders", foreign_keys=[user_id]
    )
    doctor: Mapped[Optional["User"]] = relationship(
        back_populates="doctor_orders", foreign_keys=[doctor_id]
    )
    blanks: Mapped[list["Blank"]] = relationship(back_populates="order")


class Blank(Base):
    __tablename__ = "blanks"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    order_id: Mapped[int] = mapped_column(ForeignKey("orders.id"))
    integration_id: Mapped[Optional[str]] = mapped_column(
        String(255), unique=True
    )

    name: Mapped[Optional[str]] = mapped_column(String(255))
    visit_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    file: Mapped[Optional[str]] = mapped_column(String(255))

    modified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=text("CURRENT_TIMESTAMP"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )

    # Relationships
    order: Mapped["Order"] = relationship(back_populates="blanks")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    token: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
