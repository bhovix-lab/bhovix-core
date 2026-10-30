"""Extraction schema used by the S4 extract tests."""

from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=80)
    amount: Decimal
    requested_action: Literal["lookup_record", "create_draft_record", "delete_record"]
