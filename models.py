from datetime import datetime
from sqlalchemy import String, Integer, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from db import Base

class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    from_user: Mapped[str] = mapped_column(String(50), index=True)
    to_user: Mapped[str] = mapped_column(String(50), index=True)

    iv_b64: Mapped[str] = mapped_column(String(200))
    ct_b64: Mapped[str] = mapped_column(Text)

    enc_key_to_b64: Mapped[str] = mapped_column(Text)
    enc_key_from_b64: Mapped[str] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True) 