from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

WalletAddress = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=26, max_length=128),
]


class Transaction(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tx_hash: str | None = None
    timestamp: datetime
    value: float = Field(ge=0)
    counterparty: str | None = None
    method: str | None = None
    gas_price: float | None = Field(default=None, ge=0)


class FundingSource(BaseModel):
    model_config = ConfigDict(extra="ignore")

    address: str
    amount: float = Field(ge=0)
    timestamp: datetime
    source_type: str | None = None


class Fingerprint(BaseModel):
    model_config = ConfigDict(extra="ignore")

    transactions: list[Transaction] = Field(default_factory=list)
    funding_sources: list[FundingSource] = Field(default_factory=list)
    interaction_sequence: list[str] = Field(default_factory=list)
    account_age_days: int = Field(default=0, ge=0)
    unique_contracts: int = Field(default=0, ge=0)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    wallet_address: WalletAddress = Field(alias="walletAddress")
    fingerprint: Fingerprint


class RuleResult(BaseModel):
    name: str
    tripped: bool
    score: float = Field(ge=0, le=100)
    detail: str | None = None


class AnalyzeResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    wallet_address: WalletAddress = Field(serialization_alias="walletAddress")
    is_human: bool
    risk_score: int = Field(ge=0, le=100)
    flags: list[str]
    rules: list[RuleResult]
