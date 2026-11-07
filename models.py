"""Request/response models for the PolicyChecker API."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, StringConstraints, field_validator

import config
from classifications import SecurityLevel
from link_checker import LinkStatus

# Leading/trailing spaces are removed, so a name of only spaces is rejected.
NameText = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=config.MAX_NAME_LENGTH)
]
DescriptionText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=config.MAX_DESCRIPTION_LENGTH
    ),
]


class StrictModel(BaseModel):
    # Unknown fields are rejected rather than silently ignored.
    model_config = ConfigDict(extra="forbid")


class Dataset(StrictModel):
    Name: NameText
    Description: DescriptionText
    SecurityClassification: SecurityLevel
    PolicyLink: HttpUrl

    @field_validator("PolicyLink")
    @classmethod
    def require_https(cls, v: HttpUrl) -> HttpUrl:
        if v.scheme != "https":
            raise ValueError("PolicyLink must use HTTPS")
        return v


class ClassificationRequest(StrictModel):
    Datasets: list[Dataset] = Field(min_length=config.MIN_DATASETS, max_length=config.MAX_DATASETS)


class PolicyLinkCheck(BaseModel):
    Name: str
    PolicyLink: str
    Status: LinkStatus
    Reachable: bool | None = None
    StatusCode: int | None = None
    Error: str | None = None


class ClassificationResponse(BaseModel):
    Datasets: list[Dataset]
    ResultingSecurityClassification: SecurityLevel
    # True: every link responded. False: at least one failed or was blocked.
    # None: no failures, but at least one link was not checked.
    AllPolicyLinksReachable: bool | None
    PolicyChecks: list[PolicyLinkCheck]
    AuditLogId: str
