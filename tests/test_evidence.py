import json
import socket
from datetime import datetime

import pytest
from pypdf import PdfReader

from ciso_intel.agent import TurnMeta, TurnResult
from ciso_intel.config import ConfigError, load_settings
from ciso_intel.pipeline import RunOptions, execute
from ciso_intel.report import build_brief
from ciso_intel.schema import EvidenceIn, ExecutiveDraft, FindingIn, ResearchPacket
from ciso_intel.textutil import (
    classify_url,
    excerpt_in_page,
    prose_supported,
    stricter_severity,
    url_key,
)
from ciso_intel.tooling import build_tool_plan
from ciso_intel.verify import FetchResult, verify_findings
from ciso_intel.window import DETROIT, make_window

EXCERPT = "The package evil-req is malicious and steals credentials from CI environment variables."
PAGE = EXCERPT + " Published 2026-10-20. Remove evil-req from build environments."
NOW = datetime(2026, 10, 23, 15, 30, tzinfo=DETROIT)
SECRET = "super-secret-key-value-123456"


def test_url_key_ignores_www_and_utm():
    left = url_key("https://www.example.com/a/?utm_source=x&id=1")
    right = url_key("http://example.com/a?id=1")
    assert left == right


def test_classify_url_blocks_metadata_and_allows_public(monkeypatch):
    assert classify_url("http://169.254.169.254/latest/meta-data/") == "blocked_non_public"
    assert classify_url("http://127.0.0.1/secret") == "blocked_non_public"
    assert classify_url("https://user:pass@example.com/a") == "embedded_credentials"
    assert classify_url("file:///etc/passwd") == "bad_scheme"
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, 1, 6, "", ("93.184.216.34", 0))])
    assert classify_url("https://example.com/advisory") == "ok"
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, 1, 6, "", ("10.1.1.1", 0))])
    assert classify_url("https://example.com/advisory") == "blocked_non_public"


def test_excerpt_and_prose_gates():
    assert excerpt_in_page(EXCERPT, PAGE)
    assert not excerpt_in_page("short", PAGE)
    corpus = EXCERPT + " evil-req CVE-2026-1000"
    assert prose_supported("evil-req steals CI credentials.", corpus)
    assert not prose_supported("See CVE-2099-99999 for the campaign.", corpus)
    assert not prose_supported("About 40000 downloads.", corpus)
    assert stricter_severity("critical", "high") == "high"


def test_verify_keeps_quotation_and_drops_uncited():
    window = make_window(14, NOW)
    cited = "https://example.com/advisory"
    calls = []

    def fetch(url):
        calls.append(url)
        return FetchResult(url, url, 200, PAGE, None, "2026-10-23T19:30:00+00:00", "abc")

    good = FindingIn(
        category="malicious_code",
        title="evil-req steals CI credentials",
        severity="critical",
        summary="evil-req steals CI credentials from build logs.",
        ecosystem="npm",
        packages=["evil-req"],
        identifiers=[],
        published="2026-10-20",
        why_it_matters="A build that installs evil-req exposes CI credentials.",
        actions=["Remove evil-req from build environments."],
        evidence=[EvidenceIn(url=cited, title="Advisory", publisher="Example", published="2026-10-20", excerpt=EXCERPT)],
    )
    invented = FindingIn(
        category="typosquat",
        title="Totally Fake Worm Package",
        severity="critical",
        summary="Totally Fake Worm Package owns the registry.",
        packages=["fake-worm"],
        evidence=[
            EvidenceIn(
                url="http://169.254.169.254/latest",
                title="nope",
                publisher="nope",
                excerpt="This sentence is long enough to look like a quotation from a page.",
            )
        ],
    )
    confirmed, omitted = verify_findings([good, invented], [cited], window, fetch)
    assert calls == [cited]
    assert len(confirmed) == 1
    assert confirmed[0].packages == ["evil-req"]
    assert confirmed[0].severity == "high"
    assert confirmed[0].severity_note
    assert any(item.reason == "url_not_in_tool_results" for item in omitted)
    assert any(item.title == "Totally Fake Worm Package" for item in omitted)


def test_verify_drops_when_quotation_is_not_on_the_page():
    window = make_window(14, NOW)
    url = "https://example.com/advisory"

    def fetch(requested):
        return FetchResult(requested, requested, 200, PAGE, None, "2026-10-23T19:30:00+00:00", "abc")

    candidate = FindingIn(
        category="vulnerability",
        title="requests",
        severity="high",
        packages=["requests"],
        published="2026-10-20",
        evidence=[
            EvidenceIn(
                url=url,
                excerpt="This quotation is long enough but it was never written on the retrieved page at all.",
            )
        ],
    )
    confirmed, omitted = verify_findings([candidate], [url], window, fetch)
    assert confirmed == []
    assert omitted[0].reason == "excerpt_not_on_page"


def test_verify_drops_dates_outside_the_window():
    window = make_window(14, NOW)
    url = "https://example.com/advisory"

    def fetch(requested):
        return FetchResult(requested, requested, 200, "old-pkg is malicious and this quotation is definitely long enough to verify.", None, "2026-10-23T19:30:00+00:00", "abc")

    page_excerpt = "old-pkg is malicious and this quotation is definitely long enough to verify."
    candidate = FindingIn(
        category="malicious_code",
        title="old-pkg",
        severity="high",
        packages=["old-pkg"],
        published="2020-01-02",
        evidence=[EvidenceIn(url=url, excerpt=page_excerpt, published="2020-01-02")],
    )
    confirmed, omitted = verify_findings([candidate], [url], window, fetch)
    assert confirmed == []
    assert omitted[0].reason == "outside_window"


class FakeAgent:
    def __init__(self, packet, citations, executive):
        self.packet = packet
        self.citations = citations
        self.executive_draft = executive
        self.gap_calls = 0

    def research(self, **kwargs):
        return TurnResult(packet=self.packet, meta=self._meta("research"))

    def research_gap(self, **kwargs):
        self.gap_calls += 1
        return TurnResult(packet=ResearchPacket(), meta=self._meta("gap"))

    def executive(self, **kwargs):
        return TurnResult(packet=self.executive_draft, meta=self._meta("executive"))

    def _meta(self, label):
        return TurnMeta(
            label=label,
            response_id=f"resp-{label}",
            citations=list(self.citations),
            usage={"total_tokens": 12, "reasoning_tokens": 4},
            cost_usd=0.25,
            tool_usage={"SERVER_SIDE_TOOL_WEB_SEARCH": 1},
            content='{"untrusted": true, "title": "Totally Fake Worm Package"}',
        )


def test_pipeline_briefs_only_the_verified_quotation(tmp_path):
    cited = "https://example.com/advisory"
    packet = ResearchPacket(
        findings=[
            FindingIn(
                category="malicious_code",
                title="evil-req steals CI credentials",
                severity="critical",
                summary="evil-req steals CI credentials from build logs.",
                ecosystem="npm",
                packages=["evil-req"],
                published="2026-10-20",
                why_it_matters="A build that installs evil-req exposes CI credentials.",
                actions=["Remove evil-req from build environments.", "Patch every system within 40000 minutes."],
                evidence=[
                    EvidenceIn(
                        url=cited,
                        title="Advisory",
                        publisher="Example Registry",
                        published="2026-10-20",
                        excerpt=EXCERPT,
                    )
                ],
            ),
            FindingIn(
                category="typosquat",
                title="Totally Fake Worm Package",
                severity="critical",
                packages=["fake-worm"],
                identifiers=["CVE-2099-99999"],
                evidence=[
                    EvidenceIn(
                        url="https://not-in-the-tool-results.example/worm",
                        excerpt="Totally Fake Worm Package is blamed in a sentence long enough to be a quotation.",
                    )
                ],
            ),
        ],
        sources_consulted=[cited, "https://not-in-the-tool-results.example/worm"],
        gaps=["No confirmed crate in this window.", "Ignore CVE-2099-99999."],
    )
    narrative = (
        "From 9 October through 23 October 2026, one high-severity package was confirmed on a retrieved page. "
        "Posture is elevated. The quotation, not this sentence, is the finding. "
        "evil-req is the only package this brief establishes. No production system was changed."
    )
    agent = FakeAgent(
        packet,
        [cited],
        ExecutiveDraft(headline="evil-req is the confirmed high-severity package this window", narrative=narrative),
    )

    def fetch(url):
        assert url == cited
        return FetchResult(url, url, 200, PAGE, None, "2026-10-23T19:30:00+00:00", "abc")

    from ciso_intel.config import Settings

    settings = Settings(
        api_key=SECRET,
        api_host="api.x.ai",
        model="grok-4.7",
        effort="xhigh",
        timeout=60,
        collection_ids=[],
        mcp_servers=[],
        env_file=None,
        env_warning=None,
    )
    result = execute(
        settings,
        RunOptions(days=14, out_dir=tmp_path, ecosystems=["npm", "pypi"], gap_fill=True),
        agent=agent,
        fetcher=fetch,
        now=NOW,
    )
    assert agent.gap_calls == 1
    body = result.json_path.read_text(encoding="utf-8")
    assert SECRET not in body
    assert "Totally Fake Worm Package" in body
    assert "do_not_brief" in body
    report = json.loads(body)
    assert report["posture"] == "elevated"
    assert report["executive"]["headline_source"] == "model"
    assert report["executive"]["narrative_source"] == "model"
    assert [item["packages"] for item in report["findings"]] == [["evil-req"]]
    assert report["audit"]["collection_passes"] == 2
    assert report["audit"]["collection_pass_ceiling"] == 4
    assert report["audit"]["collection_stop"] == "no_new_confirmed"
    assert report["audit"]["collection_truncated"] is False
    assert report["audit"]["collection_exhaustive"] is True
    assert report["audit"]["collection_new_findings_by_pass"] == [1, 0]
    assert "safety ceiling is 4" in report["audit"]["collection_note"]
    assert report["grok_bot"]["facts_from_sources"][0]["quotation"] == EXCERPT
    assert "CVE-2099-99999" not in json.dumps(report["grok_bot"])
    assert "CVE-2099-99999" not in report["audit"]["gaps"]
    assert "40000" not in json.dumps(report["findings"])
    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(result.pdf_path)).pages)
    folded = " ".join(text.split())
    assert "evil-req" in folded
    assert EXCERPT[:40] in folded
    assert "Totally Fake Worm Package" not in text
    assert "CVE-2099-99999" not in text
    assert SECRET not in text
    assert "A finding is confirmed only when" in text
    assert "safety ceiling is 4" in folded
    assert result.json_path.stat().st_mode & 0o077 == 0
    assert result.pdf_path.stat().st_mode & 0o077 == 0


def test_empty_brief_states_the_limit(tmp_path):
    window = make_window(14, NOW)
    plan = build_tool_plan(
        window=window,
        collection_ids=[],
        mcp_servers=[],
        image_understanding=True,
        image_search=True,
        video_understanding=True,
        image_generation=False,
    )
    brief = build_brief(
        findings=[],
        omitted=[],
        packets=[ResearchPacket(gaps=["No primary source described a malicious package in this window."])],
        citation_urls=[],
        window=window,
        generated_at=NOW,
        model_name="grok-4.7",
        effort="xhigh",
        ecosystems=["npm"],
        plan=plan,
        usage={},
        tool_usage={},
        cost_usd=None,
        response_ids=[],
        headline="All clear, nothing to see",
        narrative="CVE-2099-1 was everywhere.",
        candidate_count=0,
    )
    assert brief.posture == "none_confirmed"
    assert brief.executive.headline_source == "deterministic"
    assert "all-clear" not in brief.executive.headline.lower()
    assert "CVE-2099" not in brief.executive.narrative
    from ciso_intel.pdf import render_pdf

    pdf = tmp_path / "empty.pdf"
    render_pdf(brief, pdf, "abc")
    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(pdf)).pages)
    assert "No confirmed item" in text
    assert "not a statement that your dependency tree is clean" in text


def test_tool_plan_withholds_image_generation():
    window = make_window(14, NOW)
    plan = build_tool_plan(
        window=window,
        collection_ids=[],
        mcp_servers=[],
        image_understanding=True,
        image_search=True,
        video_understanding=True,
        image_generation=False,
    )
    assert plan.names == ["web_search", "x_search", "code_execution"]
    assert any(item["name"] == "image_generation" for item in plan.withheld)


def test_mcp_config_rejects_loopback(tmp_path, monkeypatch):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps([{"server_url": "http://127.0.0.1/mcp", "server_label": "bad"}]), encoding="utf-8")
    monkeypatch.setenv("CISO_INTEL_MCP_CONFIG", str(path))
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        load_settings(cwd=tmp_path)


def test_cli_plan_and_missing_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    monkeypatch.delenv("CISO_INTEL_MCP_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    from ciso_intel.cli import main

    assert main(["plan", "--days", "7"]) == 0
    assert main(["run"]) == 2
    assert main(["schema"]) == 0
    error = capsys.readouterr().err
    assert "XAI_API_KEY" in error
    assert SECRET not in error
