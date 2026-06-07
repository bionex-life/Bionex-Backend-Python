from datetime import datetime
from pydantic import BaseModel, Field, model_validator


class StepLogCreate(BaseModel):
    step_count: int = Field(..., ge=0, description="Step count must be 0 or positive")
    date_time_from: datetime = Field(
        ..., description="Start of the step count interval"
    )
    date_time_to: datetime = Field(..., description="End of the step count interval")

    @model_validator(mode="after")
    def validate_interval(self) -> "StepLogCreate":
        if self.date_time_from >= self.date_time_to:
            raise ValueError("date_time_from must be strictly less than date_time_to")
        return self


class StepIngestionResponse(BaseModel):
    daily_total: int
