from datetime import datetime
from typing import List, Literal
from pydantic import BaseModel, Field, model_validator


class SleepRecord(BaseModel):
    model_config = {
        "populate_by_name": True
    }

    period_from: datetime = Field(..., alias="from", description="Start of the sleep interval")
    period_to: datetime = Field(..., alias="to", description="End of the sleep interval")
    sleep_type: Literal["main", "nap"] = Field("main", description="Type of sleep ('main' or 'nap')")

    @model_validator(mode="after")
    def validate_interval(self) -> "SleepRecord":
        if self.period_from >= self.period_to:
            raise ValueError("from time must be strictly less than to time")
        return self


class SleepIngestionRequest(BaseModel):
    records: List[SleepRecord]


class SleepIngestionResponse(BaseModel):
    success: bool = True
    message: str = "Sleep records ingested successfully"
