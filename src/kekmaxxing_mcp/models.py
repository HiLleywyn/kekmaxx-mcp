"""Strict public-source investigation contracts."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def now() -> str:
    return datetime.now(UTC).isoformat()


def canonical(value) -> str:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )


def digest(value: str | bytes) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def public_reference(url: str) -> str:
    """Offline syntax check for stored citations; network collection validates DNS."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username:
        raise ValueError("Expected a public HTTP(S) citation without credentials")
    if parsed.port not in {None, 80, 443}:
        raise ValueError("Citation must use a standard web port")
    if parsed.hostname in {"localhost", "localhost.localdomain"} or "." not in parsed.hostname:
        raise ValueError("Citation must identify a public host")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ValueError("Private-address citations are not accepted")
    if any(
        key.casefold() in {"api_key", "token", "access_token", "password", "client_secret"}
        for key, _ in parse_qsl(parsed.query)
    ):
        raise ValueError("Do not store credential-bearing citation URLs")
    return url


def redact(text: str) -> str:
    text = re.sub(r"(?i)\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", "[email redacted]", text)
    text = re.sub(r"\b(?:ghp|github_pat|sk)_[A-Za-z0-9_-]{16,}\b", "[secret redacted]", text)
    text = re.sub(
        r"(?<!\w)(?:\+\d{1,3}[ -])?\(?\d{3}\)?[ -]\d{3}[ -]\d{4}\b", "[phone redacted]", text
    )
    text = re.sub(
        r'(?i)((?:api_key|access_token|client_secret|password)["\s:=]+)'
        r'[^\s,"&]+',
        r"\1[secret redacted]",
        text,
    )
    return text


class Status(StrEnum):
    documented = "directly_documented"
    corroborated = "independently_corroborated"
    inferred = "supported_inference"
    weak = "weak_indication"
    disputed = "disputed"
    contradicted = "contradicted"
    unverified = "unverified"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Evidence(Strict):
    source_url: str = Field(max_length=4000)
    source_type: str = Field(min_length=1, max_length=80)
    content: str = Field(max_length=200_000)
    retrieved_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    published_at: datetime | None = None
    original_id: str = Field(default="", max_length=200)
    extraction_method: str = Field(default="manual_public_excerpt", max_length=120)
    extraction_version: str = "1"
    observation: str = Field(default="direct", pattern="^(direct|inference)$")
    confidence: float = Field(default=0.5, ge=0, le=1)
    limitations: list[str] = Field(default_factory=list, max_length=30)
    status: Status = Status.unverified
    independent_source_group: str = Field(default="", max_length=200)
    collection_errors: list[str] = Field(default_factory=list, max_length=30)
    supersedes: str | None = None
    artifact_sha256: str | None = Field(default=None, pattern="^[a-f0-9]{64}$")
    artifact_reference: str | None = Field(default=None, max_length=200)

    _source = field_validator("source_url")(public_reference)

    @field_validator("retrieved_at", "published_at")
    @classmethod
    def aware(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Timestamps require an explicit timezone")
        return value.astimezone(UTC) if value else None

    @field_validator("artifact_reference")
    @classmethod
    def artifact(cls, value):
        if value and (value.startswith(("/", "\\")) or ":" in value or ".." in value):
            raise ValueError("Artifact references must be relative, without traversal")
        return value


class Entity(Strict):
    name: str = Field(min_length=1, max_length=200)
    entity_type: str = Field(
        pattern="^(organization|domain|website|social_account|committee|vendor|"
        "public_official|publication|advertisement|document|event)$"
    )
    aliases: list[str] = Field(default_factory=list, max_length=50)
    identifiers: dict[str, str] = Field(default_factory=dict, max_length=30)
    public_scope: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)


class Relationship(Strict):
    source: str
    target: str
    relationship_type: str = Field(min_length=1, max_length=80, pattern="^[a-z][a-z0-9_]+$")
    evidence_ids: list[str] = Field(min_length=1, max_length=100)
    status: Status = Status.unverified
    strength: float = Field(default=1, ge=0, le=1)
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    alternative_explanations: list[str] = Field(default_factory=list, max_length=30)
    contradicting_evidence_ids: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def interval(self):
        for stamp in [self.valid_from, self.valid_to]:
            if stamp is not None and stamp.tzinfo is None:
                raise ValueError("Temporal edges require timezone-aware timestamps")
        if self.valid_from and self.valid_to and self.valid_from > self.valid_to:
            raise ValueError("Invalid edge validity interval")
        return self


class Assertion(Strict):
    text: str = Field(min_length=1, max_length=10_000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    contradicting_evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    status: Status = Status.unverified
    occurred_at: datetime | None = None
    predictions: list[str] = Field(default_factory=list, max_length=30)
    alternative_explanations: list[str] = Field(default_factory=list, max_length=30)
    next_steps: list[str] = Field(default_factory=list, max_length=30)
    priority: int = Field(default=3, ge=1, le=5)

    @model_validator(mode="after")
    def supported(self):
        if self.status != Status.unverified and not self.evidence_ids:
            raise ValueError("Assessed assertions require supporting evidence")
        if self.occurred_at is not None and self.occurred_at.tzinfo is None:
            raise ValueError("Dated assertions require a timezone")
        return self


RECORD_MODELS = {
    "evidence": Evidence,
    "entity": Entity,
    "relationship": Relationship,
    "claim": Assertion,
    "hypothesis": Assertion,
    "note": Assertion,
    "question": Assertion,
    "event": Assertion,
}
