"""Build the CISO brief from verified findings. Unverified text does not get a seat."""

from __future__ import annotations

import json
import re
from datetime import datetime
from uuid import uuid4

from ciso_intel.prompts import CATEGORIES
from ciso_intel.schema import (
    ActionItem,
    Brief,
    Executive,
    Fact,
    FindingRecord,
    GrokBotPacket,
    Inference,
    Omission,
    ResearchPacket,
)
from ciso_intel.textutil import SEVERITY_ORDER, find_ids, mismatches_posture, norm, overclaims, prose_supported, url_key
from ciso_intel.tooling import ToolPlan
from ciso_intel.window import DETROIT, Window

READ_THIS_FIRST = (
    "Brief only from findings and from grok_bot.facts_from_sources. "
    "Each fact is a quotation retrieved during this run. "
    "audit.omitted is an exclusion log, not intelligence. "
    "Inferences are paraphrases and lose to the quotation when they disagree. "
    "An empty finding list is not an all-clear for your environment. This run cannot see your lockfiles."
)

BOT_INSTRUCTIONS = (
    "You are briefing a CISO from this JSON file. Use only grok_bot.facts_from_sources as facts. "
    "Each fact's quotation was copied from the cited page during the run that wrote this file. "
    "Inferences are paraphrases; if one disagrees with its quotation, drop the inference. "
    "actions_for_approval are not done. actions_completed only describes this research run. "
    "If a question is not answered by the facts, say the brief does not establish that. "
    "Do not add packages, model ids, vulnerabilities, authors, licenses, dates, download counts, or victims from memory. "
    "A malicious_model fact is a Hugging Face model the source calls malicious, backdoored, or carrying a payload. "
    "A vulnerable_model fact is a model the source documents as vulnerable, and is not malware unless the quotation says so. "
    "A similar name is not a typosquat and is not a malicious model. "
    "Do not use audit.omitted. Do not describe an empty fact list as an all-clear."
)

CATEGORY_LABELS = dict(CATEGORIES)
CATEGORY_SHORT = {
    "malicious_code": "Malicious code",
    "vulnerability": "Vulnerabilities",
    "malicious_author": "Authors",
    "license_risk": "License risk",
    "typosquat": "Typosquats",
    "malicious_model": "Malicious models",
    "vulnerable_model": "Vulnerable models",
}
CATEGORY_NOUNS = {
    "malicious_code": ("malicious package", "malicious packages"),
    "vulnerability": ("vulnerability", "vulnerabilities"),
    "malicious_author": ("author", "authors"),
    "license_risk": ("license event", "license events"),
    "typosquat": ("typosquat", "typosquats"),
    "malicious_model": ("malicious model", "malicious models"),
    "vulnerable_model": ("vulnerable model", "vulnerable models"),
}
POSTURE_LABELS = {
    "severe": "Severe",
    "elevated": "Elevated",
    "guarded": "Guarded",
    "none_confirmed": "No confirmed items",
}


def assign_ids(findings: list[FindingRecord]) -> list[FindingRecord]:
    ordered = sorted(
        findings,
        key=lambda item: (-SEVERITY_ORDER.index(item.severity), item.category, item.title.lower()),
    )
    ranked = []
    for index, finding in enumerate(ordered, start=1):
        ranked.append(finding.model_copy(update={"id": f"F-{index:03d}"}))
    return ranked


def posture_of(findings: list[FindingRecord]) -> tuple[str, str, str]:
    severities = {item.severity for item in findings}
    if not findings:
        return (
            "none_confirmed",
            POSTURE_LABELS["none_confirmed"],
            "No candidate passed page verification in this window.",
        )
    if "critical" in severities:
        return ("severe", POSTURE_LABELS["severe"], "At least one confirmed finding is critical.")
    if "high" in severities:
        return ("elevated", POSTURE_LABELS["elevated"], "At least one confirmed finding is high severity.")
    return ("guarded", POSTURE_LABELS["guarded"], "Confirmed findings are medium severity or lower.")


def build_brief(
    *,
    findings: list[FindingRecord],
    omitted: list[Omission],
    packets: list[ResearchPacket],
    citation_urls: list[str],
    window: Window,
    generated_at: datetime,
    model_name: str,
    effort: str,
    ecosystems: list[str],
    plan: ToolPlan,
    usage: dict,
    tool_usage: dict,
    cost_usd: float | None,
    response_ids: list[str],
    headline: str | None,
    narrative: str | None,
    candidate_count: int,
    collection: dict | None = None,
) -> Brief:
    findings = assign_ids(findings)
    posture, posture_label, posture_basis = posture_of(findings)
    corpus = _support_corpus(findings, window, candidate_count, len(omitted))
    severities = {item.severity for item in findings}
    headline_source = "deterministic"
    narrative_source = "deterministic"
    final_headline = _deterministic_headline(posture, findings)
    final_narrative = _deterministic_narrative(window, findings, len(omitted), posture_label)
    if findings and headline and _executive_ok(headline, corpus, severities, posture, kind="headline"):
        final_headline = headline.strip()
        headline_source = "model"
    if findings and narrative and _executive_ok(narrative, corpus, severities, posture, kind="narrative"):
        final_narrative = narrative.strip()
        narrative_source = "model"
    actions = _priority_actions(findings)
    executive = Executive(
        headline=final_headline,
        narrative=final_narrative,
        headline_source=headline_source,
        narrative_source=narrative_source,
        priority_actions=actions,
    )
    gaps = _safe_gaps(packets, findings, omitted, citation_urls)
    sources = _safe_sources(packets, citation_urls)
    coverage_note = collection.get("note") if collection and collection.get("truncated") else None
    grok_bot = _grok_bot(
        findings,
        window,
        generated_at,
        gaps,
        len(omitted),
        executive,
        coverage_note=coverage_note,
    )
    local = generated_at.astimezone(DETROIT)
    report_id = f"CISO-OSINT-{local.strftime('%Y%m%d-%H%M')}-{uuid4().hex[:4]}"
    audit = {
        "candidates": candidate_count,
        "confirmed": len(findings),
        "omitted_count": len(omitted),
        "omitted_by_reason": _reason_counts(omitted),
        "omitted": [item.model_dump() for item in omitted],
        "omitted_are_not_intelligence": True,
        "gaps": gaps,
        "sources_consulted": sources,
        "tool_usage": tool_usage,
        "token_usage": usage,
        "cost_usd": cost_usd,
        "response_ids": response_ids,
        "executive_headline_source": headline_source,
        "executive_narrative_source": narrative_source,
        "evidence_standard": (
            "A finding is confirmed only when a tool in this run cited the URL, this program fetched the page, "
            "a verbatim excerpt was present, and the model id, package, identifier, or author was on that page."
        ),
    }
    if collection:
        audit["collection_passes"] = collection["passes"]
        audit["collection_pass_ceiling"] = collection["ceiling"]
        audit["collection_stop"] = collection["stop"]
        audit["collection_truncated"] = collection["truncated"]
        audit["collection_exhaustive"] = collection["exhaustive"]
        audit["collection_note"] = collection["note"]
        audit["collection_new_findings_by_pass"] = collection["new_by_pass"]
    return Brief(
        read_this_first=READ_THIS_FIRST,
        report_id=report_id,
        generated_at=local.isoformat(timespec="seconds"),
        timezone="America/Detroit",
        window=window.as_dict(),
        posture=posture,
        posture_label=posture_label,
        posture_basis=posture_basis,
        model={
            "name": model_name,
            "reasoning_effort": effort,
            "knowledge_cutoff": "2026-05",
            "provider": "SpaceXSI",
            "api": "xAI gRPC chat, documented Responses-compatible tools",
        },
        tools_enabled=plan.enabled,
        tools_withheld=plan.withheld,
        ecosystems=ecosystems,
        executive=executive,
        findings=findings,
        grok_bot=grok_bot,
        audit=audit,
    )


def _deterministic_headline(posture: str, findings: list[FindingRecord]) -> str:
    if posture == "none_confirmed":
        return "No open-source finding survived source verification in this window"
    if posture == "severe":
        return "Critical open-source exposure confirmed in this window"
    if posture == "elevated":
        return "High-severity open-source exposure confirmed in this window"
    count = len(findings)
    noun = "item" if count == 1 else "items"
    return f"{count} limited open-source {noun} confirmed in this window"


def _deterministic_narrative(window: Window, findings: list[FindingRecord], omitted: int, posture_label: str) -> str:
    if omitted == 0:
        excluded = "No candidate was excluded."
    elif omitted == 1:
        excluded = "1 candidate failed that check and is not briefed."
    else:
        excluded = f"{omitted} candidates failed that check and are not briefed."
    if not findings:
        return (
            f"From {window.label}, Grok searched the open web and X, and this program re-fetched every cited page. "
            "A finding is briefed only when a verbatim passage on that page contains the model id, package, identifier, or author. "
            f"None did. {excluded} "
            "Absence from this brief is not a statement that your dependency tree is clean. This run cannot see your lockfiles."
        )
    counts = []
    for key, _label in CATEGORIES:
        count = sum(1 for item in findings if item.category == key)
        if count:
            singular, plural = CATEGORY_NOUNS[key]
            counts.append(f"{count} {singular if count == 1 else plural}")
    joined = _join(counts)
    return (
        f"From {window.label}, {len(findings)} item{'s' if len(findings) != 1 else ''} passed page-level verification"
        f"{': ' + joined if joined else ''}. Posture is {posture_label}. "
        "Each item in this brief carries a quotation retrieved during this run. "
        f"{excluded} "
        "The paraphrase under a quotation, when one is shown, is subordinate to that quotation."
    )


def _executive_ok(text: str, corpus: str, severities: set[str], posture: str, *, kind: str) -> bool:
    cleaned = text.strip()
    if kind == "headline" and not 12 <= len(cleaned) <= 140:
        return False
    if kind == "narrative" and not 80 <= len(cleaned) <= 1400:
        return False
    folded = norm(cleaned)
    if not prose_supported(cleaned, corpus, allow_urls=False):
        return False
    if overclaims(cleaned, severities, posture) or mismatches_posture(cleaned, posture):
        return False
    if "critical" in severities and re.search(r"\bhigh-severity\b", folded) and not re.search(r"\bcritical\b", folded):
        return False
    return True


def _support_corpus(findings: list[FindingRecord], window: Window, candidates: int, omitted: int) -> str:
    parts = [
        window.label,
        window.start.isoformat(),
        window.end.isoformat(),
        str(window.start.year),
        str(len(findings)),
        str(candidates),
        str(omitted),
        str(window.end.day),
        str(window.start.day),
    ]
    for finding in findings:
        parts.extend(
            [
                finding.id,
                finding.title,
                finding.paraphrase or "",
                finding.why_it_matters or "",
                finding.ecosystem,
                finding.severity,
                " ".join(finding.packages),
                " ".join(finding.identifiers),
                " ".join(finding.actors),
                " ".join(finding.actions),
            ]
        )
        for evidence in finding.evidence:
            parts.extend([evidence.excerpt, evidence.title, evidence.publisher, evidence.host, evidence.published or ""])
    return "\n".join(parts)


def _priority_actions(findings: list[FindingRecord]) -> list[str]:
    actions = []
    seen = set()
    for finding in findings:
        for action in finding.actions:
            marker = norm(action)
            if marker in seen:
                continue
            seen.add(marker)
            actions.append(action)
            if len(actions) == 6:
                return actions
    return actions


def _safe_gaps(packets: list[ResearchPacket], findings: list[FindingRecord], omitted: list[Omission], citations: list[str]) -> list[str]:
    corpus = "\n".join(
        [
            " ".join(finding.packages + finding.identifiers + finding.actors + [finding.title, finding.paraphrase or ""])
            for finding in findings
        ]
        + [" ".join(item.excerpt for finding in findings for item in finding.evidence)]
        + citations
        + ["2024 2025 2026 2027"]
    )
    confirmed_norm = norm(corpus)
    blocked = set()
    for item in omitted:
        folded_title = norm(item.title)
        if len(folded_title) >= 8 and folded_title not in confirmed_norm:
            blocked.add(folded_title)
        for identifier in find_ids(item.title):
            if identifier.lower() not in confirmed_norm:
                blocked.add(identifier.lower())
    kept = []
    for packet in packets:
        for gap in packet.gaps:
            text = gap.strip()
            if not text or text in kept:
                continue
            if not prose_supported(text, corpus, allow_urls=True):
                continue
            folded = norm(text)
            if any(token in folded for token in blocked):
                continue
            kept.append(text)
    return kept[:12]


def _safe_sources(packets: list[ResearchPacket], citations: list[str]) -> list[str]:
    allowed = {url_key(url) for url in citations}
    kept = []
    for packet in packets:
        for url in packet.sources_consulted:
            if url_key(url) in allowed and url not in kept:
                kept.append(url)
    return kept


def _grok_bot(
    findings,
    window: Window,
    generated_at: datetime,
    gaps: list[str],
    omitted_count: int,
    executive: Executive,
    *,
    coverage_note: str | None = None,
) -> GrokBotPacket:
    facts = []
    inferences = []
    actions = []
    for finding in findings:
        for evidence in finding.evidence:
            facts.append(
                Fact(
                    id=finding.id,
                    category=finding.category,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    ecosystem=finding.ecosystem,
                    packages=finding.packages,
                    identifiers=finding.identifiers,
                    actors=finding.actors,
                    quotation=evidence.excerpt,
                    source_url=evidence.url,
                    source_title=evidence.title,
                    source_host=evidence.host,
                    published=evidence.published or finding.published,
                    retrieved_at=evidence.retrieved_at,
                )
            )
        if finding.paraphrase:
            inferences.append(Inference(finding_id=finding.id, text=finding.paraphrase, basis="paraphrase_of_quotation"))
        for action in finding.actions:
            actions.append(ActionItem(finding_id=finding.id, text=action, status="not_started"))
    unresolved = [
        "This run has no view of your lockfiles, registries, or build systems.",
        f"{omitted_count} candidate{'s' if omitted_count != 1 else ''} {'were' if omitted_count != 1 else 'was'} excluded. Those exclusions are not findings.",
        *gaps,
    ]
    if coverage_note:
        unresolved.append(coverage_note)
    if executive.narrative_source == "deterministic":
        unresolved.append("The executive narrative was written from the confirmed counts, not from an extra model pass.")
    return GrokBotPacket(
        schema_version="1.0.0",
        purpose="Attach this object, or the whole report file, to a Grok Bot. The bot briefs only from facts_from_sources.",
        instructions=BOT_INSTRUCTIONS,
        as_of=generated_at.astimezone(DETROIT).isoformat(timespec="seconds"),
        timezone="America/Detroit",
        window=window.as_dict(),
        facts_from_sources=facts,
        inferences=inferences,
        actions_completed=[
            "Searched open sources with the configured Grok tools and re-fetched cited pages. No registry, repository, or production system was changed."
        ],
        actions_for_approval=actions,
        unresolved=unresolved,
    )


def _reason_counts(omitted: list[Omission]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in omitted:
        counts[item.reason] = counts.get(item.reason, 0) + 1
    return counts


def _join(parts: list[str]) -> str:
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return f"{parts[0]} and {parts[1]}"
    return ", ".join(parts[:-1]) + f", and {parts[-1]}"


def brief_json(brief: Brief) -> str:
    return json.dumps(brief.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"
