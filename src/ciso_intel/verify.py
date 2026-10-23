"""Re-fetch cited pages and keep a finding only when the quotation is really there."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO

import httpx
from bs4 import BeautifulSoup
from pypdf import PdfReader

from ciso_intel.schema import EvidenceIn, EvidenceRecord, FindingIn, FindingRecord, Omission
from ciso_intel.textutil import (
    clean_token,
    clean_url,
    classify_url,
    excerpt_in_page,
    host_of,
    is_primary,
    is_social,
    needle_in,
    norm,
    normalize_severity,
    prose_supported,
    severity_cap_from_page,
    stricter_severity,
    url_key,
)
from ciso_intel.window import Window, parse_date

MAX_BYTES = 1_500_000
USER_AGENT = "ciso-intel/1.0 (source verification)"

CATEGORY_ALIASES = {
    "malicious_code": "malicious_code",
    "malicious": "malicious_code",
    "malware": "malicious_code",
    "malicious package": "malicious_code",
    "vulnerability": "vulnerability",
    "vuln": "vulnerability",
    "cve": "vulnerability",
    "malicious_author": "malicious_author",
    "author": "malicious_author",
    "actor": "malicious_author",
    "license_risk": "license_risk",
    "license": "license_risk",
    "typosquat": "typosquat",
    "typosquatting": "typosquat",
    "typosquats": "typosquat",
}

REASON_RANK = {
    "identifier_not_on_page": 6,
    "excerpt_not_on_page": 5,
    "excerpt_too_short": 4,
    "not_refetched": 3,
    "unsupported_content": 3,
    "empty_page": 3,
    "dns_failed": 2,
    "blocked_non_public": 1,
    "bad_url": 1,
    "bad_scheme": 1,
    "bad_host": 1,
    "bad_port": 1,
    "embedded_credentials": 1,
    "url_not_in_tool_results": 0,
    "no_evidence": 0,
    "unknown_category": 0,
    "no_specific_identifier": 0,
    "outside_window": 7,
    "duplicate": 0,
}


@dataclass
class FetchResult:
    url: str
    final_url: str | None
    status: int | None
    text: str
    error: str | None
    retrieved_at: str
    content_sha256: str | None


class CitationIndex:
    def __init__(self, urls: list[str]) -> None:
        self.keys: set[str] = set()
        self.status_ids: set[str] = set()
        for url in urls:
            key = url_key(url)
            if key:
                self.keys.add(key)
            match = re.search(r"/status(?:es)?/(\d+)", url)
            if match:
                self.status_ids.add(match.group(1))

    def contains(self, url: str) -> bool:
        key = url_key(url)
        if key and key in self.keys:
            return True
        match = re.search(r"/status(?:es)?/(\d+)", url)
        return bool(match and match.group(1) in self.status_ids)


class HttpFetcher:
    def __init__(self, *, timeout: float = 20.0) -> None:
        self.timeout = timeout

    def __call__(self, url: str) -> FetchResult:
        retrieved = datetime.now(timezone.utc).isoformat(timespec="seconds")
        decision = classify_url(url)
        if decision != "ok":
            return FetchResult(url, None, None, "", decision, retrieved, None)

        def guard(request: httpx.Request) -> None:
            later = classify_url(str(request.url))
            if later != "ok":
                raise httpx.RequestError(f"blocked redirect: {later}")

        try:
            with httpx.Client(
                timeout=httpx.Timeout(self.timeout, connect=10.0),
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/pdf,application/json;q=0.9,*/*;q=0.1"},
                event_hooks={"request": [guard]},
            ) as client:
                with client.stream("GET", url) as response:
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_bytes():
                        total += len(chunk)
                        if total > MAX_BYTES:
                            break
                        chunks.append(chunk)
                    data = b"".join(chunks)
                    status = response.status_code
                    content_type = response.headers.get("content-type", "")
                    final_url = str(response.url)
        except httpx.TimeoutException:
            return FetchResult(url, None, None, "", "not_refetched", retrieved, None)
        except httpx.HTTPError:
            return FetchResult(url, None, None, "", "not_refetched", retrieved, None)
        if status != 200:
            return FetchResult(url, final_url, status, "", "not_refetched", retrieved, None)
        text = _extract_text(data, content_type)
        if text is None:
            return FetchResult(url, final_url, status, "", "unsupported_content", retrieved, None)
        if not text.strip():
            return FetchResult(url, final_url, status, "", "empty_page", retrieved, None)
        digest = hashlib.sha256(norm(text).encode("utf-8")).hexdigest()
        return FetchResult(url, final_url, status, text, None, retrieved, digest)


def verify_findings(
    candidates: list[FindingIn],
    citation_urls: list[str],
    window: Window,
    fetch,
) -> tuple[list[FindingRecord], list[Omission]]:
    index = CitationIndex(citation_urls)
    cache: dict[str, FetchResult] = {}
    confirmed: list[FindingRecord] = []
    omitted: list[Omission] = []
    seen: set[tuple] = set()

    def cached(url: str) -> FetchResult:
        if url not in cache:
            cache[url] = fetch(url)
        return cache[url]

    for candidate in candidates:
        category = CATEGORY_ALIASES.get(norm(candidate.category).replace(" ", "_"), "")
        if not category:
            category = CATEGORY_ALIASES.get(norm(candidate.category), "")
        if not category:
            omitted.append(Omission(reason="unknown_category", category=candidate.category or "unknown", title=candidate.title, evidence=[]))
            continue
        record, omission = _check_one(candidate, category, index, window, cached)
        if omission is not None:
            omitted.append(omission)
            continue
        assert record is not None
        key = _dedupe_key(record)
        if key in seen:
            omitted.append(Omission(reason="duplicate", category=category, title=record.title, evidence=[]))
            continue
        seen.add(key)
        confirmed.append(record)
    return confirmed, omitted


def _check_one(candidate, category, index, window, fetch) -> tuple[FindingRecord | None, Omission | None]:
    packages = _tokens(candidate.packages)
    identifiers = [token.upper() if token.upper().startswith(("CVE-", "GHSA-", "PYSEC-", "MAL-", "OSV-")) else token for token in _tokens(candidate.identifiers)]
    actors = _tokens(candidate.actors)
    needles = [item for item in packages + identifiers + actors if len(norm(item)) >= 4]
    if not needles:
        return None, Omission(reason="no_specific_identifier", category=category, title=candidate.title, evidence=[])
    if not candidate.evidence:
        return None, Omission(reason="no_evidence", category=category, title=candidate.title, evidence=[])

    kept: list[EvidenceRecord] = []
    pages: list[str] = []
    failures: list[dict] = []
    for item in candidate.evidence:
        record, failure, page = _check_evidence(item, needles, index, fetch)
        if failure is not None:
            failures.append(failure)
        if record is not None and page is not None:
            kept.append(record)
            pages.append(page)
    if not kept:
        reason = _best_reason(failures)
        return None, Omission(reason=reason, category=category, title=candidate.title, evidence=failures)

    date_status = _date_status(candidate.published, [item.published for item in kept], window)
    if date_status in {"before", "after"}:
        return None, Omission(
            reason="outside_window",
            category=category,
            title=candidate.title,
            evidence=[{"url": item.url, "reason": "outside_window"} for item in kept],
        )

    page_blob = "\n".join(pages)
    claimed = normalize_severity(candidate.severity)
    hosts = [item.host for item in kept]
    social_only = bool(hosts) and all(is_social(host) for host in hosts)
    ceiling = severity_cap_from_page(page_blob)
    if social_only:
        ceiling = stricter_severity(ceiling, "medium")
    elif not any(is_primary(host) for host in hosts):
        ceiling = stricter_severity(ceiling, "high")
    severity = stricter_severity(claimed, ceiling)
    note = None
    if severity != claimed and social_only:
        note = f"Reported as {claimed}. Capped at {severity} because the only source is a social post."
    elif severity != claimed and not any(is_primary(host) for host in hosts):
        note = f"Reported as {claimed}. Capped at {severity} because the source is not on the primary-advisory list."
    elif severity != claimed:
        note = f"Reported as {claimed}. Capped at {severity} based on the language of the retrieved page."

    corpus = _claim_corpus(kept, packages, identifiers, actors)
    title = candidate.title.strip()
    if not prose_supported(title, corpus, allow_urls=False):
        title = packages[0] if packages else identifiers[0] if identifiers else actors[0]
    paraphrase = candidate.summary.strip()
    if not paraphrase or not prose_supported(paraphrase, corpus, allow_urls=False) or norm(paraphrase) == norm(kept[0].excerpt):
        paraphrase_out = None
    else:
        paraphrase_out = paraphrase
    why = candidate.why_it_matters.strip()
    why_out = why if why and prose_supported(why, corpus, allow_urls=False) else None
    actions = []
    for action in candidate.actions:
        text = action.strip()
        if not text or not prose_supported(text, corpus, allow_urls=False):
            continue
        folded = norm(text)
        if any(needle_in(needle, folded) for needle in needles):
            actions.append(text)
        if len(actions) == 4:
            break

    confidence, basis = _confidence(hosts, date_status)
    record = FindingRecord(
        id="",
        category=category,
        title=title,
        severity=severity,
        claimed_severity=claimed,
        severity_note=note,
        ecosystem=(candidate.ecosystem or "").strip().lower(),
        packages=packages,
        identifiers=identifiers,
        actors=actors,
        published=candidate.published if parse_date(candidate.published) else None,
        paraphrase=paraphrase_out,
        why_it_matters=why_out,
        actions=actions,
        confidence=confidence,
        confidence_basis=basis,
        social_only=social_only,
        evidence=kept,
    )
    return record, None


def _check_evidence(item: EvidenceIn, needles: list[str], index: CitationIndex, fetch) -> tuple[EvidenceRecord | None, dict | None, str | None]:
    url = clean_url(item.url)
    if not index.contains(url):
        return None, {"url": url, "reason": "url_not_in_tool_results", "url_in_tool_results": False}, None
    decision = classify_url(url)
    if decision != "ok":
        return None, {"url": url, "reason": decision, "url_in_tool_results": True}, None
    if len(norm(item.excerpt)) < 40:
        return None, {"url": url, "reason": "excerpt_too_short", "url_in_tool_results": True}, None
    result = fetch(url)
    if result.error or not result.text:
        return None, {"url": url, "reason": result.error or "not_refetched", "url_in_tool_results": True, "http_status": result.status}, None
    if not excerpt_in_page(item.excerpt, result.text):
        return None, {"url": url, "reason": "excerpt_not_on_page", "url_in_tool_results": True, "http_status": result.status}, None
    folded = norm(result.text)
    if not any(needle_in(needle, folded) for needle in needles):
        return None, {"url": url, "reason": "identifier_not_on_page", "url_in_tool_results": True, "http_status": result.status}, None
    host = host_of(result.final_url or url)
    record = EvidenceRecord(
        url=url,
        title=(item.title or "").strip(),
        publisher=(item.publisher or "").strip(),
        host=host,
        published=item.published if parse_date(item.published) else None,
        excerpt=re.sub(r"\s+", " ", item.excerpt).strip(),
        http_status=result.status or 0,
        retrieved_at=result.retrieved_at,
        content_sha256=result.content_sha256 or "",
        primary_source=is_primary(host),
    )
    return record, None, result.text


def _tokens(values: list[str]) -> list[str]:
    cleaned = []
    seen = set()
    for value in values:
        token = clean_token(value)
        if not token:
            continue
        marker = token.lower()
        if marker in seen:
            continue
        seen.add(marker)
        cleaned.append(token)
    return cleaned


def _best_reason(failures: list[dict]) -> str:
    if not failures:
        return "no_evidence"
    return max(failures, key=lambda item: REASON_RANK.get(item.get("reason", ""), 0))["reason"]


def _date_status(published: str | None, evidence_dates: list[str | None], window: Window) -> str:
    parsed = [item for item in [parse_date(published), *[parse_date(value) for value in evidence_dates]] if item]
    if not parsed:
        return "undated"
    if any(window.start <= item <= window.end for item in parsed):
        return "in_window"
    if all(item < window.start for item in parsed):
        return "before"
    return "after"


def _confidence(hosts: list[str], date_status: str) -> tuple[str, str]:
    if hosts and all(is_social(host) for host in hosts):
        return "low", "The only retrieved source is a social post."
    primary = any(is_primary(host) for host in hosts)
    if not primary:
        return "medium", "The retrieved page is outside the primary-advisory host list."
    if date_status == "in_window":
        return "high", "A primary source was retrieved and states a date inside the window."
    return "medium", "A primary source was retrieved. It did not state a date inside the window."


def _claim_corpus(evidence: list[EvidenceRecord], packages: list[str], identifiers: list[str], actors: list[str]) -> str:
    """Facts the paraphrase is allowed to use: the quotation and the identifiers found on the page.

    The model's own summary is not part of this text, so it cannot justify itself.
    """
    parts = [*packages, *identifiers, *actors]
    for item in evidence:
        parts.extend([item.excerpt, item.title, item.publisher, item.host, item.url, item.published or ""])
    return "\n".join(part for part in parts if part)


def _dedupe_key(finding: FindingRecord) -> tuple:
    if finding.identifiers:
        return ("id", tuple(sorted(item.lower() for item in finding.identifiers)))
    if finding.packages:
        return ("pkg", finding.category, tuple(sorted(item.lower() for item in finding.packages)))
    return ("title", finding.category, norm(finding.title))


def _extract_text(data: bytes, content_type: str) -> str | None:
    folded = content_type.lower()
    if data.startswith(b"%PDF") or "pdf" in folded:
        try:
            reader = PdfReader(BytesIO(data))
        except Exception:
            return None
        pages = []
        for page in reader.pages[:30]:
            try:
                pages.append(page.extract_text() or "")
            except Exception:
                continue
        return "\n".join(pages)
    if data.startswith(b"\x89PNG") or data.startswith(b"\xff\xd8") or folded.startswith("image/"):
        return None
    if "html" in folded or data.lstrip()[:1] == b"<" or b"<html" in data[:500].lower():
        soup = BeautifulSoup(data, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        return soup.get_text(" ", strip=True)
    if "json" in folded or "text/" in folded or "xml" in folded or not folded:
        return data.decode("utf-8", errors="replace")
    return data.decode("utf-8", errors="replace")
