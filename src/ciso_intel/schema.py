"""Shapes exchanged with Grok and written for the CISO."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class EvidenceIn(BaseModel):
    """A quotation the model claims to have copied from a tool result."""

    model_config = ConfigDict(extra="ignore")

    url: str
    title: str = ""
    publisher: str = ""
    published: str | None = None
    excerpt: str = ""


class FindingIn(BaseModel):
    """One candidate. Nothing in this object is briefed until verification passes."""

    model_config = ConfigDict(extra="ignore")

    category: str
    title: str
    severity: str = "informational"
    summary: str = ""
    ecosystem: str = ""
    packages: list[str] = Field(default_factory=list)
    identifiers: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    published: str | None = None
    why_it_matters: str = ""
    actions: list[str] = Field(default_factory=list)
    evidence: list[EvidenceIn] = Field(default_factory=list)
    confidence: str = "low"


class ResearchPacket(BaseModel):
    model_config = ConfigDict(extra="ignore")

    findings: list[FindingIn] = Field(default_factory=list)
    sources_consulted: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


class ExecutiveDraft(BaseModel):
    model_config = ConfigDict(extra="ignore")

    headline: str = ""
    narrative: str = ""


class EvidenceRecord(BaseModel):
    url: str
    title: str
    publisher: str
    host: str
    published: str | None
    excerpt: str
    http_status: int
    retrieved_at: str
    content_sha256: str
    primary_source: bool


class FindingRecord(BaseModel):
    id: str
    category: str
    title: str
    severity: str
    claimed_severity: str
    severity_note: str | None = None
    ecosystem: str
    packages: list[str]
    identifiers: list[str]
    actors: list[str]
    published: str | None
    paraphrase: str | None = None
    why_it_matters: str | None = None
    actions: list[str]
    confidence: str
    confidence_basis: str
    social_only: bool
    evidence: list[EvidenceRecord]


class Omission(BaseModel):
    reason: str
    category: str
    title: str
    do_not_brief: bool = True
    evidence: list[dict] = Field(default_factory=list)


class Fact(BaseModel):
    id: str
    category: str
    severity: str
    confidence: str
    ecosystem: str
    packages: list[str]
    identifiers: list[str]
    actors: list[str]
    quotation: str
    source_url: str
    source_title: str
    source_host: str
    published: str | None
    retrieved_at: str


class Inference(BaseModel):
    finding_id: str
    text: str
    basis: str


class ActionItem(BaseModel):
    finding_id: str
    text: str
    status: str = "not_started"


class GrokBotPacket(BaseModel):
    schema_version: str
    purpose: str
    instructions: str
    as_of: str
    timezone: str
    window: dict
    facts_from_sources: list[Fact]
    inferences: list[Inference]
    actions_completed: list[str]
    actions_for_approval: list[ActionItem]
    unresolved: list[str]


class Executive(BaseModel):
    headline: str
    narrative: str
    headline_source: str
    narrative_source: str
    priority_actions: list[str]


class Brief(BaseModel):
    schema_version: str = "1.0.0"
    kind: str = "ciso_oss_intel_report"
    read_this_first: str
    report_id: str
    generated_at: str
    timezone: str
    window: dict
    posture: str
    posture_label: str
    posture_basis: str
    model: dict
    tools_enabled: list[dict]
    tools_withheld: list[dict]
    ecosystems: list[str]
    executive: Executive
    findings: list[FindingRecord]
    grok_bot: GrokBotPacket
    audit: dict
