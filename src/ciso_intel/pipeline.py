"""Run collection, verification, and the two deliverables."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

from ciso_intel.agent import GrokIntelAgent, IntelError, ModelOutputError, TurnMeta, TurnResult
from ciso_intel.config import Settings, require_key
from ciso_intel.pdf import render_pdf
from ciso_intel.prompts import (
    continuation_prompt,
    executive_prompt,
    facts_for_executive,
    research_prompt,
    system_prompt,
)
from ciso_intel.report import assign_ids, brief_json, build_brief
from ciso_intel.schema import FindingRecord, ResearchPacket
from ciso_intel.textutil import norm
from ciso_intel.tooling import build_tool_plan
from ciso_intel.verify import HttpFetcher, verify_findings
from ciso_intel.window import DETROIT, Window, WindowChoiceError, make_window, window_from_dates

# A pass that still confirms new findings would keep going. This ceiling stops a run
# that never comes back empty. The report audit records it when the stop is this ceiling.
MAX_COLLECTION_PASSES = 4


@dataclass
class RunOptions:
    days: int = 14
    out_dir: Path = Path("reports")
    ecosystems: list[str] = field(
        default_factory=lambda: ["npm", "pypi", "maven", "nuget", "rubygems", "crates", "go", "packagist"]
    )
    # When false, stop after the first pass even if it confirmed new findings.
    gap_fill: bool = True
    image_understanding: bool = True
    image_search: bool = True
    video_understanding: bool = True
    image_generation: bool = False
    window_start: date | None = None
    window_end: date | None = None
    max_passes: int = MAX_COLLECTION_PASSES


@dataclass
class RunResult:
    directory: Path
    pdf_path: Path
    json_path: Path
    sha_path: Path
    finding_count: int
    omitted_count: int
    posture: str
    report_id: str


def execute(
    settings: Settings,
    options: RunOptions,
    log=None,
    *,
    agent: GrokIntelAgent | None = None,
    fetcher=None,
    now: datetime | None = None,
) -> RunResult:
    write = log or (lambda _message: None)
    moment = now or datetime.now(DETROIT)
    window = _resolve_window(options, moment)
    ceiling = _pass_ceiling(options)
    plan = build_tool_plan(
        window=window,
        collection_ids=settings.collection_ids,
        mcp_servers=settings.mcp_servers,
        image_understanding=options.image_understanding,
        image_search=options.image_search,
        video_understanding=options.video_understanding,
        image_generation=options.image_generation,
    )
    if agent is None:
        agent = GrokIntelAgent(settings, write, api_key=require_key(settings))
    if fetcher is None:
        fetcher = HttpFetcher()
    system = system_prompt()
    write(f"Window {window.label}")
    write("Tools: " + ", ".join(plan.names))
    confirmed: list[FindingRecord] = []
    omitted = []
    turns: list[TurnMeta] = []
    packets: list[ResearchPacket] = []
    passes_run = 0
    new_by_pass: list[int] = []
    stop = "no_new_confirmed"
    while passes_run < ceiling:
        pass_number = passes_run + 1
        if pass_number == 1:
            write(f"Pass {pass_number} of up to {ceiling}")
            prompt = research_prompt(window, options.ecosystems)
            try:
                result = agent.research(system=system, prompt=prompt, plan=plan, window=window)
            except ModelOutputError as exc:
                _dump_failure(options.out_dir, "research", exc)
                raise IntelError(
                    f"{exc} Untrusted model output was saved under {options.out_dir / 'failed'} and was not briefed."
                ) from exc
        else:
            if not options.gap_fill:
                stop = "single_pass"
                break
            label = f"pass-{pass_number}"
            write(
                f"Pass {pass_number} of up to {ceiling}: searching again for items not already confirmed "
                f"({len(confirmed)} so far)."
            )
            prompt = continuation_prompt(window, options.ecosystems, _known_items(confirmed))
            try:
                result = agent.research_gap(
                    system=system,
                    prompt=prompt,
                    plan=plan,
                    window=window,
                    label=label,
                )
            except ModelOutputError as exc:
                _dump_failure(options.out_dir, label, exc)
                write("A later pass did not return valid JSON. The brief uses the findings confirmed so far.")
                stop = "pass_failed"
                break
        packet = _as_research(result)
        batch_confirmed, batch_omitted = verify_findings(packet.findings, result.meta.citations, window, fetcher)
        before = len(confirmed)
        confirmed = _dedupe(confirmed + batch_confirmed)
        added = len(confirmed) - before
        omitted = omitted + batch_omitted
        turns.append(result.meta)
        packets.append(packet)
        passes_run += 1
        new_by_pass.append(added)
        write(f"Pass {pass_number} confirmed {added} new finding(s); running total {len(confirmed)}.")
        if added == 0:
            stop = "no_new_confirmed"
            break
        if passes_run >= ceiling:
            stop = "pass_ceiling"
            break
    collection = _collection_record(passes_run, ceiling, stop, new_by_pass)
    confirmed = assign_ids(confirmed)
    write(f"Verified {len(confirmed)} finding(s); excluded {len(omitted)} candidate(s).")
    write(collection["note"])
    headline, narrative, executive_meta = _executive(agent, system, window, confirmed, write, options.out_dir)
    if executive_meta is not None:
        turns.append(executive_meta)
    brief = build_brief(
        findings=confirmed,
        omitted=omitted,
        packets=packets,
        citation_urls=_all_citations(turns),
        window=window,
        generated_at=moment,
        model_name=settings.model,
        effort=settings.effort,
        ecosystems=options.ecosystems,
        plan=plan,
        usage=_sum_usage(turns),
        tool_usage=_sum_tools(turns),
        cost_usd=_sum_cost(turns),
        response_ids=[turn.response_id for turn in turns if turn.response_id],
        headline=headline,
        narrative=narrative,
        candidate_count=sum(len(item.findings) for item in packets),
        collection=collection,
    )
    return write_brief(brief, options.out_dir, turns, packets)


def write_brief(brief, out_dir: Path, turns: list[TurnMeta] | None = None, packets: list[ResearchPacket] | None = None) -> RunResult:
    directory = out_dir / brief.report_id
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    payload = brief_json(brief).encode("utf-8")
    json_path = directory / "report.json"
    pdf_path = directory / "report.pdf"
    sha_path = directory / "report.json.sha256"
    digest = hashlib.sha256(payload).hexdigest()
    _secret_file(json_path, payload)
    _secret_file(sha_path, f"{digest}  report.json\n".encode("utf-8"))
    render_pdf(brief, pdf_path, digest)
    pdf_path.chmod(0o600)
    if turns is not None:
        raw = directory / "raw"
        raw.mkdir(mode=0o700, exist_ok=True)
        _secret_file(
            raw / "README.txt",
            b"These files are untrusted model output from before verification. Do not brief from them.\n",
        )
        for turn in turns:
            _secret_file(raw / f"{turn.label}.txt", turn.content.encode("utf-8"))
            _secret_file(
                raw / f"{turn.label}.meta.json",
                json.dumps(
                    {
                        "untrusted": True,
                        "response_id": turn.response_id,
                        "citations": turn.citations,
                        "usage": turn.usage,
                        "cost_usd": turn.cost_usd,
                        "tool_usage": turn.tool_usage,
                        "tool_log": turn.tool_log,
                        "images_discarded": turn.images_discarded,
                    },
                    indent=2,
                ).encode("utf-8"),
            )
    return RunResult(
        directory=directory,
        pdf_path=pdf_path,
        json_path=json_path,
        sha_path=sha_path,
        finding_count=len(brief.findings),
        omitted_count=brief.audit["omitted_count"],
        posture=brief.posture,
        report_id=brief.report_id,
    )


def _executive(agent, system, window: Window, findings: list[FindingRecord], log, out_dir: Path):
    if not findings:
        log("No confirmed findings. Executive prose stays on the verified counts.")
        return None, None, None
    facts = json.dumps(facts_for_executive(findings), indent=2)
    from ciso_intel.report import posture_of

    posture, _label, _basis = posture_of(findings)
    try:
        result = agent.executive(
            system=system,
            prompt=executive_prompt(window, len(findings), posture, facts),
        )
    except ModelOutputError as exc:
        _dump_failure(out_dir, "executive", exc)
        log("Executive prose failed validation. The brief uses the verified counts.")
        return None, None, None
    except IntelError as exc:
        log(f"Executive pass skipped: {exc}")
        return None, None, None
    draft = result.packet
    if draft is None:
        return None, None, result.meta
    return draft.headline, draft.narrative, result.meta


def _resolve_window(options: RunOptions, moment: datetime) -> Window:
    if options.window_start is not None or options.window_end is not None:
        if options.window_start is None or options.window_end is None:
            raise IntelError("A custom window needs both a start and an end date.")
        try:
            return window_from_dates(options.window_start, options.window_end)
        except WindowChoiceError as exc:
            raise IntelError(str(exc)) from exc
    try:
        return make_window(options.days, moment)
    except ValueError as exc:
        raise IntelError(str(exc)) from exc


def _pass_ceiling(options: RunOptions) -> int:
    if options.max_passes < 1:
        raise IntelError("Collection pass ceiling must be at least 1.")
    return min(options.max_passes, MAX_COLLECTION_PASSES)


def _collection_record(passes: int, ceiling: int, stop: str, new_by_pass: list[int]) -> dict:
    truncated = stop in {"pass_ceiling", "pass_failed"}
    if stop == "pass_ceiling":
        note = (
            f"Collection stopped at the safety ceiling of {ceiling} passes "
            f"after pass {passes} still confirmed new findings. "
            "Later items in the window may be missing."
        )
    elif stop == "pass_failed":
        noun = "pass" if passes == 1 else "passes"
        note = (
            f"Collection stopped after {passes} verified {noun} "
            f"because the next pass did not return valid JSON. The safety ceiling is {ceiling} passes. "
            "Later items in the window may be missing."
        )
    elif stop == "single_pass":
        note = (
            "Collection stopped after the first pass because continuation was turned off. "
            f"The safety ceiling is {ceiling} passes."
        )
    else:
        noun = "pass" if passes == 1 else "passes"
        note = (
            f"Collection ran {passes} {noun} and stopped because the last pass confirmed no new findings. "
            f"The safety ceiling is {ceiling} passes."
        )
    return {
        "passes": passes,
        "ceiling": ceiling,
        "stop": stop,
        "truncated": truncated,
        "exhaustive": stop == "no_new_confirmed",
        "note": note,
        "new_by_pass": list(new_by_pass),
    }


def _known_items(findings: list[FindingRecord]) -> list[str]:
    rows = []
    for item in findings:
        parts = [item.title]
        if item.packages:
            parts.append("packages: " + ", ".join(item.packages))
        if item.identifiers:
            parts.append("identifiers: " + ", ".join(item.identifiers))
        if item.actors:
            parts.append("authors: " + ", ".join(item.actors))
        rows.append(" | ".join(parts))
    return rows


def _as_research(result: TurnResult) -> ResearchPacket:
    if not isinstance(result.packet, ResearchPacket):
        raise IntelError("Research pass did not return findings.")
    return result.packet


def _dedupe(findings: list[FindingRecord]) -> list[FindingRecord]:
    seen = set()
    kept = []
    for finding in findings:
        if finding.identifiers:
            key = ("id", tuple(sorted(norm(item) for item in finding.identifiers)))
        elif finding.packages:
            key = ("pkg", finding.category, tuple(sorted(norm(item) for item in finding.packages)))
        else:
            key = ("title", finding.category, norm(finding.title))
        if key in seen:
            continue
        seen.add(key)
        kept.append(finding)
    return kept


def _all_citations(turns: list[TurnMeta]) -> list[str]:
    found = []
    for turn in turns:
        for url in turn.citations:
            if url not in found:
                found.append(url)
    return found


def _sum_usage(turns: list[TurnMeta]) -> dict:
    total: dict[str, int] = {}
    for turn in turns:
        for key, value in turn.usage.items():
            total[key] = total.get(key, 0) + int(value or 0)
    return total


def _sum_tools(turns: list[TurnMeta]) -> dict:
    total: dict[str, int] = {}
    for turn in turns:
        for key, value in turn.tool_usage.items():
            total[key] = total.get(key, 0) + int(value or 0)
    return total


def _sum_cost(turns: list[TurnMeta]) -> float | None:
    costs = [turn.cost_usd for turn in turns if turn.cost_usd is not None]
    if not costs:
        return None
    return float(sum(costs))


def _dump_failure(out_dir: Path, label: str, exc: ModelOutputError) -> None:
    failed = out_dir / "failed"
    failed.mkdir(parents=True, mode=0o700, exist_ok=True)
    _secret_file(
        failed / f"{label}.txt",
        (exc.content or "").encode("utf-8"),
    )
    _secret_file(failed / f"{label}.error.txt", exc.detail.encode("utf-8"))


def _secret_file(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)
