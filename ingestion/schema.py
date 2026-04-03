import uuid
from datetime import datetime
from typing import Optional, Dict

from pydantic import BaseModel, Field

class AlertSchema(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: str
    raw_log: str
    iocs: dict = Field(default_factory=dict)
    severity_raw: Optional[float] = None
    label: Optional[int] = None
