import enum
from sqlalchemy import Column, Integer, String, DateTime, Text, Enum
from sqlalchemy.sql import func
from database import Base


class ServiceType(str, enum.Enum):
    SSH  = "SSH"
    HTTP = "HTTP"
    FTP  = "FTP"


class EventSeverity(str, enum.Enum):
    LOW    = "Low"
    MEDIUM = "Medium"
    HIGH   = "High"


class HoneypotEvent(Base):
    __tablename__ = "honeypot_events"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    service = Column(Enum(ServiceType), nullable=False, index=True)

    source_ip   = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, nullable=True)

    username = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)

    raw_payload = Column(Text, nullable=True)

    country      = Column(String(100), nullable=True)
    country_code = Column(String(2),   nullable=True)
    city         = Column(String(100), nullable=True)

    severity = Column(
        Enum(EventSeverity),
        default=EventSeverity.MEDIUM,
        nullable=False,
        index=True,
    )

    def __repr__(self) -> str:
        return (
            f"<HoneypotEvent id={self.id} service={self.service} "
            f"ip={self.source_ip} severity={self.severity}>"
        )