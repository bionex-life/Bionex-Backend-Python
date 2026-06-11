from datetime import date
from typing import Optional, Dict, Any, List, Union
from pydantic import BaseModel

class DailyHealthRecord(BaseModel):
    record_date: date
    health_score: Optional[Union[int, dict, Any]] = None
    sleep_quality: Optional[Dict[str, Any]] = None
    step_count: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True

class DailyHealthResponse(BaseModel):
    data: List[DailyHealthRecord]
