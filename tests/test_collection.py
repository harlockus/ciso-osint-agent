"""Exhaustive collection and the time-frame question. These tests do not call the API."""

import json
import sys
from datetime import datetime
from io import StringIO

import pytest
from pypdf import PdfReader

from ciso_intel.agent import ModelOutputError, TurnMeta, TurnResult
from ciso_intel.config import Settings
from ciso_intel.pipeline import MAX_COLLECTION_PASSES, RunOptions, execute
from ciso_intel.prompts import continuation_prompt, research_prompt, system_prompt
from ciso_intel.schema import EvidenceIn, ExecutiveDraft, FindingIn, ResearchPacket
from ciso_intel.verify import FetchResult
from ciso_intel.window import (
    DETROIT,
    WindowChoiceError,
    make_window,
    parse_window_choice,
    prompt_for_window,
)

NOW = datetime(2026, 10, 23, 15, 30, tzinfo=DETROIT)
UNIT_KEY = "unit-test-key"


def test_prompts_ask_for_every_qualifying_item_and_keep_the_evidence_rules():
    window = make_window(14, NOW)
    research = research_prompt(window, ["npm", "pypi"])
    follow = continuation_prompt(window, ["npm"], ["pkg-alpha | packages: pkg-alpha"])
    system = system_prompt()
    assert "at most" not in research.lower()
    assert "at most" not in follow.lower()
    assert "every item in this window" in research
    assert "pkg-alpha" in follow
    assert "Do not stop because a category already has a confirmed finding" in follow
    assert "Search every category" in follow
    assert "confirmed nothing" not in follow
    assert "change a decision this week" not in system
    assert "exhaustive collection" in system
    assert "40 to 320 characters" in system
    assert "Do not dump unrelated CVEs" in system
    assert "An empty findings list is a correct result." in system
    assert "malicious_model" in research
    assert "vulnerable_model" in research
    assert "malicious_model" in follow
    assert "vulnerable_model" in follow
    assert "malicious_model" in system
    assert "vulnerable_model" in system
    assert "huggingface.co" in system
    assert "org/name" in system
    assert "similar name" in system.lower()
    assert "not a malicious model" in system
    hf = research_prompt(window, ["npm", "huggingface"])
    assert "huggingface.co" in hf
    assert "Protect AI" in hf
    assert "JFrog" in hf
    assert "HiddenLayer" in hf
    assert "malicious_model" in hf
    assert "vulnerable_model" in hf
    follow_hf = continuation_prompt(window, ["huggingface"], ["acme/poison-bert"])
    assert "huggingface.co" in follow_hf
    assert "acme/poison-bert" in follow_hf
    assert "malicious_model" in follow_hf
    assert "vulnerable_model" in follow_hf
    assert "huggingface" in RunOptions().ecosystems
    assert RunOptions().max_passes == MAX_COLLECTION_PASSES == 4
    assert not hasattr(RunOptions(), "finding_limit")


def test_parse_window_choice_accepts_days_or_inclusive_dates():
    assert parse_window_choice("14", NOW) == make_window(14, NOW)
    assert parse_window_choice("14 days", NOW) == make_window(14, NOW)
    assert parse_window_choice("", NOW, default_days=14) == make_window(14, NOW)
    chosen = parse_window_choice("2026-10-01 to 2026-10-23", NOW)
    assert chosen.start.isoformat() == "2026-10-01"
    assert chosen.end.isoformat() == "2026-10-23"
    single = parse_window_choice("2026-10-23 2026-10-23", NOW)
    assert single.start == single.end
    with pytest.raises(WindowChoiceError):
        parse_window_choice("2026-10-20 2026-10-01", NOW)
    with pytest.raises(WindowChoiceError):
        parse_window_choice("2026-01-01 2026-10-23", NOW)
    with pytest.raises(WindowChoiceError):
        parse_window_choice("2026-10-01 2026-10-24", NOW)
    with pytest.raises(WindowChoiceError):
        parse_window_choice("0", NOW)
    with pytest.raises(WindowChoiceError):
        parse_window_choice("2026-10-01", NOW)


def test_prompt_shows_the_window_and_waits_for_yes():
    out = StringIO()
    stdin = _Lines(["nope\n", "10\n", "n\n", "\n", "Y\n"])
    window = prompt_for_window(stdin, out, NOW, suggested_days=14)
    assert window == make_window(14, NOW)
    text = out.getvalue()
    assert "America/Detroit" in text
    assert "Inclusive window:" in text
    assert "Type y to confirm" in text
    assert "Enter the time frame again." in text
    assert "Suggested: 14 days" in text

    out = StringIO()
    stdin = _Lines(["2026-10-10 2026-10-23\n", "yes\n"])
    window = prompt_for_window(stdin, out, NOW, suggested_days=14)
    assert window.start.isoformat() == "2026-10-10"
    assert window.end.isoformat() == "2026-10-23"
    with pytest.raises(EOFError):
        prompt_for_window(_Lines([]), StringIO(), NOW)


def test_later_passes_keep_more_malicious_packages_in_a_category_that_already_hit(tmp_path):
    first, first_page = _malicious("pkg-alpha")
    second, second_page = _malicious("pkg-bravo")
    stale, stale_page = _malicious("old-pkg", published="2020-01-02")
    pages = {
        first.evidence[0].url: first_page,
        second.evidence[0].url: second_page,
        stale.evidence[0].url: stale_page,
    }
    agent = ScriptedAgent(
        [
            ResearchPacket(findings=[first]),
            ResearchPacket(findings=[second, stale]),
            ResearchPacket(),
        ]
    )
    result = _run(tmp_path, agent, pages)
    report = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert agent.gap_calls == 2
    assert [item["packages"] for item in report["findings"]] == [["pkg-alpha"], ["pkg-bravo"]]
    assert {item["category"] for item in report["findings"]} == {"malicious_code"}
    assert report["audit"]["collection_passes"] == 3
    assert report["audit"]["collection_new_findings_by_pass"] == [1, 1, 0]
    assert report["audit"]["collection_stop"] == "no_new_confirmed"
    assert report["audit"]["collection_truncated"] is False
    assert report["audit"]["collection_exhaustive"] is True
    assert report["audit"]["collection_pass_ceiling"] == 4
    assert any(item["reason"] == "outside_window" and item["do_not_brief"] for item in report["audit"]["omitted"])
    facts = json.dumps(report["grok_bot"]["facts_from_sources"])
    assert "old-pkg" not in facts
    assert "pkg-bravo" in facts
    assert "at most" not in agent.prompts[0].lower()
    assert "every item in this window" in agent.prompts[0]
    assert "pkg-alpha" in agent.prompts[1]
    assert "Do not stop because a category already has a confirmed finding" in agent.prompts[1]
    assert "confirmed nothing" not in agent.prompts[1]
    assert "change a decision this week" not in agent.systems[0]
    assert UNIT_KEY not in result.json_path.read_text(encoding="utf-8")
    assert (result.directory / "raw" / "research.txt").is_file()
    assert (result.directory / "raw" / "pass-2.txt").is_file()
    assert (result.directory / "raw" / "pass-3.txt").is_file()


def test_a_pass_that_confirms_nothing_new_stops_before_the_ceiling(tmp_path):
    first, page = _malicious("pkg-alpha")
    stale, stale_page = _malicious("old-pkg", published="2020-01-02")
    pages = {first.evidence[0].url: page, stale.evidence[0].url: stale_page}
    agent = ScriptedAgent(
        [
            ResearchPacket(findings=[first]),
            ResearchPacket(findings=[stale]),
            ResearchPacket(findings=[_malicious("pkg-bravo")[0]]),
        ]
    )
    result = _run(tmp_path, agent, pages)
    report = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert agent.gap_calls == 1
    assert len(agent.packets) == 1
    assert [item["packages"] for item in report["findings"]] == [["pkg-alpha"]]
    assert report["audit"]["collection_stop"] == "no_new_confirmed"
    assert report["audit"]["collection_passes"] == 2
    assert report["audit"]["omitted"][0]["reason"] == "outside_window"


def test_safety_ceiling_is_visible_when_the_last_pass_still_finds_something(tmp_path):
    packets = []
    pages = {}
    names = ["pkg-aaaa", "pkg-bbbb", "pkg-cccc", "pkg-dddd", "pkg-eeee"]
    for name in names:
        finding, page = _malicious(name)
        packets.append(ResearchPacket(findings=[finding]))
        pages[finding.evidence[0].url] = page
    agent = ScriptedAgent(packets)
    result = _run(tmp_path, agent, pages, max_passes=9)
    report = json.loads(result.json_path.read_text(encoding="utf-8"))
    confirmed = [item["packages"][0] for item in report["findings"]]
    assert confirmed == names[:4]
    assert "pkg-eeee" not in result.json_path.read_text(encoding="utf-8")
    assert agent.gap_calls == 3
    assert len(agent.packets) == 1
    assert report["audit"]["collection_passes"] == 4
    assert report["audit"]["collection_pass_ceiling"] == 4
    assert report["audit"]["collection_stop"] == "pass_ceiling"
    assert report["audit"]["collection_truncated"] is True
    assert report["audit"]["collection_exhaustive"] is False
    assert report["audit"]["collection_new_findings_by_pass"] == [1, 1, 1, 1]
    assert "safety ceiling of 4" in report["audit"]["collection_note"]
    assert "may be missing" in report["audit"]["collection_note"]
    assert any("may be missing" in item for item in report["grok_bot"]["unresolved"])
    folded = _pdf_text(result.pdf_path)
    assert "safety ceiling of 4" in folded
    assert "pkg-dddd" in folded
    assert "pkg-eeee" not in folded
    assert (result.directory / "raw" / "pass-4.txt").is_file()
    assert not (result.directory / "raw" / "pass-5.txt").exists()


def test_lower_ceiling_stops_while_findings_remain(tmp_path):
    first, first_page = _malicious("pkg-one")
    second, second_page = _malicious("pkg-two")
    third, third_page = _malicious("pkg-three")
    pages = {
        first.evidence[0].url: first_page,
        second.evidence[0].url: second_page,
        third.evidence[0].url: third_page,
    }
    agent = ScriptedAgent(
        [
            ResearchPacket(findings=[first]),
            ResearchPacket(findings=[second]),
            ResearchPacket(findings=[third]),
        ]
    )
    result = _run(tmp_path, agent, pages, max_passes=2)
    report = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert [item["packages"][0] for item in report["findings"]] == ["pkg-one", "pkg-two"]
    assert report["audit"]["collection_pass_ceiling"] == 2
    assert report["audit"]["collection_truncated"] is True
    assert "pkg-three" not in result.json_path.read_text(encoding="utf-8")
    assert "safety ceiling of 2" in _pdf_text(result.pdf_path)


def test_empty_first_pass_does_not_keep_searching(tmp_path):
    agent = ScriptedAgent([ResearchPacket(), ResearchPacket(findings=[_malicious("pkg-alpha")[0]])])
    result = _run(tmp_path, agent, {})
    report = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert agent.gap_calls == 0
    assert report["findings"] == []
    assert report["audit"]["collection_passes"] == 1
    assert report["audit"]["collection_stop"] == "no_new_confirmed"
    assert report["audit"]["collection_exhaustive"] is True
    assert report["audit"]["collection_truncated"] is False


def test_no_gap_fill_stops_after_the_first_confirmed_batch(tmp_path):
    first, page = _malicious("pkg-alpha")
    agent = ScriptedAgent([ResearchPacket(findings=[first]), ResearchPacket(findings=[_malicious("pkg-bravo")[0]])])
    result = _run(tmp_path, agent, {first.evidence[0].url: page}, gap_fill=False)
    report = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert agent.gap_calls == 0
    assert [item["packages"] for item in report["findings"]] == [["pkg-alpha"]]
    assert report["audit"]["collection_stop"] == "single_pass"
    assert report["audit"]["collection_exhaustive"] is False
    assert report["audit"]["collection_truncated"] is False
    assert "safety ceiling is 4" in report["audit"]["collection_note"]


def test_a_failed_later_pass_keeps_confirmed_findings_and_marks_the_run(tmp_path):
    first, page = _malicious("pkg-alpha")

    class FailGap(ScriptedAgent):
        def research_gap(self, **kwargs):
            self.gap_calls += 1
            raise ModelOutputError("not json", "schema mismatch")

    agent = FailGap([ResearchPacket(findings=[first])])
    result = _run(tmp_path, agent, {first.evidence[0].url: page})
    report = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert [item["packages"] for item in report["findings"]] == [["pkg-alpha"]]
    assert report["audit"]["collection_stop"] == "pass_failed"
    assert report["audit"]["collection_truncated"] is True
    assert any("may be missing" in item for item in report["grok_bot"]["unresolved"])
    assert (tmp_path / "failed" / "pass-2.txt").read_text(encoding="utf-8") == "not json"
    assert UNIT_KEY not in (tmp_path / "failed" / "pass-2.txt").read_text(encoding="utf-8")


def test_tty_run_asks_and_a_flag_or_closed_stdin_does_not(monkeypatch, tmp_path, capsys):
    seen = _patch_run(monkeypatch, tmp_path, _Lines(["2026-10-01 2026-10-24\n", "7\n", "y\n"], tty=True))
    assert _main(["run"]) == 0
    assert seen["options"].window_start.isoformat() == "2026-10-16"
    assert seen["options"].window_end.isoformat() == "2026-10-23"
    err = capsys.readouterr().err
    assert "Inclusive window:" in err
    assert "Type y to confirm" in err
    assert UNIT_KEY not in err

    seen = _patch_run(monkeypatch, tmp_path, _GuardStdin(tty=True))
    assert _main(["run", "--days", "7"]) == 0
    assert seen["options"].window_start.isoformat() == "2026-10-16"
    assert seen["options"].window_end.isoformat() == "2026-10-23"

    monkeypatch.setenv("CISO_INTEL_LOOKBACK_DAYS", "6")
    seen = _patch_run(monkeypatch, tmp_path, _Lines(["\n", "n\n", "14\n", "Y\n"], tty=True))
    assert _main(["run"]) == 0
    assert (seen["options"].window_end - seen["options"].window_start).days == 14
    assert "Suggested: 6 days" in capsys.readouterr().err

    monkeypatch.setenv("CISO_INTEL_LOOKBACK_DAYS", "5")
    seen = _patch_run(monkeypatch, tmp_path, _GuardStdin(tty=True))
    assert _main(["run", "--yes"]) == 0
    assert (seen["options"].window_end - seen["options"].window_start).days == 5

    seen = _patch_run(monkeypatch, tmp_path, _GuardStdin(tty=False))
    monkeypatch.delenv("CISO_INTEL_LOOKBACK_DAYS", raising=False)
    assert _main(["run"]) == 0
    assert (seen["options"].window_end - seen["options"].window_start).days == 14

    seen = _patch_run(monkeypatch, tmp_path, _GuardStdin(tty=True))
    assert _main(["run", "--start", "2026-10-01", "--end", "2026-10-23"]) == 0
    assert seen["options"].window_start.isoformat() == "2026-10-01"
    assert seen["options"].window_end.isoformat() == "2026-10-23"

    seen = _patch_run(monkeypatch, tmp_path, _GuardStdin(tty=True))
    assert _main(["run", "--start", "2026-10-23", "--end", "2026-10-23", "--yes"]) == 0
    assert seen["options"].window_start == seen["options"].window_end


def test_bad_windows_and_a_missing_key_do_not_start_a_run(monkeypatch, tmp_path, capsys):
    calls = {"n": 0}

    def fake_execute(*_args, **_kwargs):
        calls["n"] += 1
        raise AssertionError("execute ran")

    _patch_run(monkeypatch, tmp_path, _GuardStdin(tty=True))
    monkeypatch.setattr("ciso_intel.cli.execute", fake_execute)
    assert _main(["run", "--days", "0"]) == 2
    assert _main(["run", "--days", "99"]) == 2
    assert _main(["run", "--start", "2026-10-23", "--end", "2026-10-01"]) == 2
    assert _main(["run", "--days", "7", "--start", "2026-10-01", "--end", "2026-10-23"]) == 2
    assert _main(["run", "--start", "10/01/2026", "--end", "2026-10-23"]) == 2
    assert _main(["run", "--start", "2026-10-01"]) == 2
    assert calls["n"] == 0
    assert UNIT_KEY not in capsys.readouterr().err

    monkeypatch.delenv("XAI_API_KEY", raising=False)
    assert _main(["run"]) == 2
    assert calls["n"] == 0


def test_plan_does_not_ask_for_a_window(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    monkeypatch.delenv("CISO_INTEL_MCP_CONFIG", raising=False)
    monkeypatch.delenv("CISO_INTEL_LOOKBACK_DAYS", raising=False)
    monkeypatch.setattr("ciso_intel.cli.datetime", _Frozen)
    monkeypatch.setattr(sys, "stdin", _GuardStdin(tty=True))
    from ciso_intel.cli import main

    assert main(["plan"]) == 0
    out = capsys.readouterr().out
    assert "9 October 2026 through 23 October 2026" in out
    assert "4 passes" in out
    assert "malicious_model" in out
    assert "vulnerable_model" in out
    assert "huggingface" in out


class _Frozen(datetime):
    @classmethod
    def now(cls, tz=None):
        if tz is None:
            return NOW.replace(tzinfo=None)
        return NOW.astimezone(tz)


class _Lines:
    def __init__(self, lines, tty=True):
        self.lines = list(lines)
        self.tty = tty

    def isatty(self):
        return self.tty

    def readline(self):
        if not self.lines:
            return ""
        return self.lines.pop(0)


class _GuardStdin:
    def __init__(self, tty):
        self.tty = tty

    def isatty(self):
        return self.tty

    def readline(self):
        raise AssertionError("time frame prompt ran")


class ScriptedAgent:
    def __init__(self, packets):
        self.packets = list(packets)
        self.prompts = []
        self.systems = []
        self.gap_calls = 0

    def research(self, **kwargs):
        self.prompts.append(kwargs["prompt"])
        self.systems.append(kwargs["system"])
        return self._result(self.packets.pop(0), "research")

    def research_gap(self, **kwargs):
        self.gap_calls += 1
        self.prompts.append(kwargs["prompt"])
        return self._result(self.packets.pop(0), kwargs.get("label", "gap"))

    def executive(self, **kwargs):
        return TurnResult(packet=ExecutiveDraft(headline="", narrative=""), meta=self._meta("executive", []))

    def _result(self, packet, label):
        urls = []
        for finding in packet.findings:
            for evidence in finding.evidence:
                if evidence.url not in urls:
                    urls.append(evidence.url)
        return TurnResult(packet=packet, meta=self._meta(label, urls))

    def _meta(self, label, citations):
        return TurnMeta(
            label=label,
            response_id=f"resp-{label}",
            citations=list(citations),
            usage={"total_tokens": 3},
            cost_usd=0.01,
            tool_usage={"SERVER_SIDE_TOOL_WEB_SEARCH": 1},
            content='{"untrusted": true}',
        )


def _malicious(package: str, *, published: str = "2026-10-20") -> tuple[FindingIn, str]:
    excerpt = f"The package {package} is malicious and steals credentials from CI environment variables."
    url = f"https://example.com/advisories/{package}"
    page = excerpt + f" Published {published}. Remove {package} from build environments."
    finding = FindingIn(
        category="malicious_code",
        title=f"{package} steals CI credentials",
        severity="high",
        summary=f"{package} steals CI credentials from build logs.",
        ecosystem="npm",
        packages=[package],
        published=published,
        why_it_matters=f"A build that installs {package} exposes CI credentials.",
        actions=[f"Remove {package} from build environments."],
        evidence=[
            EvidenceIn(
                url=url,
                title="Advisory",
                publisher="Example Registry",
                published=published,
                excerpt=excerpt,
            )
        ],
    )
    return finding, page


def _settings() -> Settings:
    return Settings(
        api_key=UNIT_KEY,
        api_host="api.x.ai",
        model="grok-4.7",
        effort="xhigh",
        timeout=60,
        collection_ids=[],
        mcp_servers=[],
        env_file=None,
        env_warning=None,
    )


def _run(tmp_path, agent, pages, **options):
    def fetch(url):
        if url not in pages:
            raise AssertionError(url)
        return FetchResult(url, url, 200, pages[url], None, "2026-10-23T19:30:00+00:00", "abc")

    return execute(
        _settings(),
        RunOptions(days=14, out_dir=tmp_path, ecosystems=["npm"], **options),
        agent=agent,
        fetcher=fetch,
        now=NOW,
    )


def _pdf_text(path) -> str:
    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
    return " ".join(text.split())


def _patch_run(monkeypatch, tmp_path, stdin):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XAI_API_KEY", UNIT_KEY)
    monkeypatch.delenv("CISO_INTEL_MCP_CONFIG", raising=False)
    monkeypatch.setattr("ciso_intel.cli.datetime", _Frozen)
    monkeypatch.setattr(sys, "stdin", stdin)
    seen = {}

    def fake_execute(_settings, options, _log):
        seen["options"] = options
        return _result(tmp_path)

    monkeypatch.setattr("ciso_intel.cli.execute", fake_execute)
    return seen


def _result(tmp_path):
    from ciso_intel.pipeline import RunResult

    return RunResult(
        directory=tmp_path,
        pdf_path=tmp_path / "report.pdf",
        json_path=tmp_path / "report.json",
        sha_path=tmp_path / "report.json.sha256",
        finding_count=0,
        omitted_count=0,
        posture="none_confirmed",
        report_id="CISO-OSINT-TEST",
    )


def _main(argv):
    from ciso_intel.cli import main

    return main(argv)
