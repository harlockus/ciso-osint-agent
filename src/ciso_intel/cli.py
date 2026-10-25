"""Command line for the CISO brief."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console

from ciso_intel import __version__
from ciso_intel.agent import IntelError
from ciso_intel.config import ConfigError, load_settings, redact, require_key
from ciso_intel.pdf import render_pdf
from ciso_intel.pipeline import DEFAULT_ECOSYSTEMS, MAX_COLLECTION_PASSES, RunOptions, execute
from ciso_intel.prompts import CATEGORIES
from ciso_intel.report import BOT_INSTRUCTIONS
from ciso_intel.schema import Brief
from ciso_intel.tooling import build_tool_plan
from ciso_intel.window import DETROIT, Window, WindowChoiceError, make_window, prompt_for_window, window_from_dates


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ciso-intel",
        description="Collect open-source threat intelligence with Grok 4.7 and brief only what a retrieved page supports.",
    )
    parser.add_argument("--env", type=Path, default=None, help="Path to the .env file. Defaults to ./.env")
    parser.add_argument("--version", action="version", version=f"ciso-intel {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Collect, verify, and write a PDF and a Grok Bot JSON file.")
    _add_run_args(run)
    run.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip the time-frame question. Use --days or --start/--end, otherwise the suggested lookback.",
    )
    plan = sub.add_parser("plan", help="Show the model, tools, and evidence rules without calling the API.")
    _add_run_args(plan)
    doctor = sub.add_parser("doctor", help="Check the key, file permissions, and that the model is listed.")
    doctor.add_argument("--env", type=Path, default=None)
    sub.add_parser("schema", help="Print the instruction block a Grok Bot should follow when this JSON is attached.")
    verify = sub.add_parser("verify", help="Re-fetch the confirmed URLs in an existing report.json.")
    verify.add_argument("json_path", type=Path)
    render = sub.add_parser("render", help="Rebuild the PDF from an existing report.json. This does not re-check claims.")
    render.add_argument("json_path", type=Path)

    # --env on the parent and on doctor. Subparsers don't inherit parent args unless parents= is set.
    args = parser.parse_args(argv)
    console = Console(stderr=True)
    stdout = Console()
    env_file = getattr(args, "env", None)
    try:
        settings = load_settings(env_file)
    except (ConfigError, ValueError) as exc:
        console.print(str(exc))
        return 2
    if settings.env_warning and args.command in {"run", "doctor", "plan"}:
        console.print(settings.env_warning)

    try:
        if args.command == "schema":
            stdout.print(BOT_INSTRUCTIONS)
            return 0
        if args.command == "plan":
            return _plan(args, settings, stdout, console)
        if args.command == "doctor":
            return _doctor(settings, stdout, console)
        if args.command == "run":
            return _run(args, settings, stdout, console)
        if args.command == "verify":
            return _verify(args.json_path, stdout, console)
        if args.command == "render":
            return _render(args.json_path, stdout, console)
    except ConfigError as exc:
        console.print(str(exc))
        return 2
    except IntelError as exc:
        console.print(redact(str(exc), settings.api_key))
        return 1
    except KeyboardInterrupt:
        console.print("Stopped.")
        return 1
    return 2


def _add_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Lookback ending today, America/Detroit (1-90). Skips the time-frame question.",
    )
    parser.add_argument(
        "--start",
        default=None,
        help="Inclusive start date YYYY-MM-DD. Use with --end. Skips the time-frame question.",
    )
    parser.add_argument(
        "--end",
        default=None,
        help="Inclusive end date YYYY-MM-DD. Use with --start. Skips the time-frame question.",
    )
    parser.add_argument("--out", type=Path, default=Path("reports"))
    parser.add_argument(
        "--ecosystems",
        default=",".join(DEFAULT_ECOSYSTEMS),
        help="Comma-separated registries, or 'all'. Includes huggingface by default.",
    )
    parser.add_argument("--no-gap-fill", action="store_true")
    parser.add_argument("--no-video", action="store_true", help="Do not enable X video understanding.")
    parser.add_argument("--no-image-tools", action="store_true", help="Do not enable image understanding or image search.")
    parser.add_argument(
        "--image-generation",
        action="store_true",
        help="Attach image generation. Generated images are discarded and never briefed.",
    )
    parser.add_argument("--env", type=Path, default=None)


def _options(args, settings, window: Window) -> RunOptions:
    ecosystems = _ecosystems(args.ecosystems)
    span = (window.end - window.start).days
    return RunOptions(
        days=span if span >= 1 else 1,
        window_start=window.start,
        window_end=window.end,
        out_dir=args.out,
        ecosystems=ecosystems,
        gap_fill=not args.no_gap_fill,
        image_understanding=not args.no_image_tools,
        image_search=not args.no_image_tools,
        video_understanding=not args.no_video,
        image_generation=args.image_generation,
    )


def _suggested_days() -> int:
    raw = os.environ.get("CISO_INTEL_LOOKBACK_DAYS")
    if raw is None or not raw.strip():
        return 14
    try:
        days = int(raw.strip())
    except ValueError as exc:
        raise ConfigError("CISO_INTEL_LOOKBACK_DAYS must be an integer from 1 to 90.") from exc
    if days < 1 or days > 90:
        raise ConfigError("CISO_INTEL_LOOKBACK_DAYS must be an integer from 1 to 90.")
    return days


def _window_from_args(args, *, stdin, stdout, now: datetime, allow_prompt: bool) -> Window:
    start_text = getattr(args, "start", None)
    end_text = getattr(args, "end", None)
    if start_text or end_text:
        if args.days is not None:
            raise ConfigError("Use either --days or --start and --end, not both.")
        if not start_text or not end_text:
            raise ConfigError("Use --start and --end together, as YYYY-MM-DD.")
        try:
            start = datetime.strptime(str(start_text).strip(), "%Y-%m-%d").date()
            end = datetime.strptime(str(end_text).strip(), "%Y-%m-%d").date()
        except ValueError as exc:
            raise ConfigError("Dates must be YYYY-MM-DD.") from exc
        try:
            return window_from_dates(start, end, today=now.astimezone(DETROIT).date())
        except WindowChoiceError as exc:
            raise ConfigError(str(exc)) from exc
    if args.days is not None:
        try:
            return make_window(args.days, now)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    suggested = _suggested_days()
    interactive = allow_prompt and stdin.isatty() and not getattr(args, "yes", False)
    if interactive:
        try:
            return prompt_for_window(stdin, stdout, now, suggested_days=suggested)
        except EOFError as exc:
            raise ConfigError(str(exc)) from exc
        except WindowChoiceError as exc:
            raise ConfigError(str(exc)) from exc
    return make_window(suggested, now)


def _ecosystems(value: str) -> list[str]:
    if value.strip().lower() in {"all", "any", "*"}:
        return []
    items = []
    for item in value.split(","):
        cleaned = item.strip().lower()
        if not cleaned:
            continue
        if not all(character.isalnum() or character in ".-+" for character in cleaned):
            raise ConfigError(f"Ecosystem name is not usable: {item}")
        items.append(cleaned)
    if not items:
        raise ConfigError("Provide at least one ecosystem, or 'all'.")
    return items


def _plan(args, settings, stdout: Console, console: Console) -> int:
    _ecosystems(args.ecosystems)
    now = datetime.now(DETROIT)
    window = _window_from_args(args, stdin=sys.stdin, stdout=sys.stderr, now=now, allow_prompt=False)
    options = _options(args, settings, window)
    plan = build_tool_plan(
        window=window,
        collection_ids=settings.collection_ids,
        mcp_servers=settings.mcp_servers,
        image_understanding=options.image_understanding,
        image_search=options.image_search,
        video_understanding=options.video_understanding,
        image_generation=options.image_generation,
    )
    stdout.print(f"ciso-intel {__version__}")
    stdout.print(f"Model {settings.model}  \u00b7  reasoning {settings.effort}  \u00b7  host {settings.api_host}")
    stdout.print(f"Window {window.label}")
    stdout.print("Ecosystems: " + (", ".join(options.ecosystems) if options.ecosystems else "all"))
    stdout.print("Enabled tools:")
    for item in plan.enabled:
        stdout.print(f"  {item['name']}  {_public_tool(item)}")
    stdout.print("Withheld:")
    for item in plan.withheld:
        stdout.print(f"  {item['name']} \u2014 {item['reason']}")
    stdout.print("Categories: " + ", ".join(key for key, _label in CATEGORIES))
    stdout.print(
        f"Collection returns every qualifying item in the window, then keeps searching until a pass "
        f"confirms nothing new or {MAX_COLLECTION_PASSES} passes. The audit records that ceiling."
    )
    stdout.print(
        "A terminal run asks for the America/Detroit window unless you pass --days, --start and --end, or --yes, "
        "or stdin is not a terminal."
    )
    stdout.print(
        "A finding is confirmed only when a tool cited the URL, this program fetched the page, "
        "a verbatim excerpt was present, and the model id, package, identifier, or author was on that page."
    )
    stdout.print("X search and grok-4.7 at xhigh are billed. Confirm current prices at https://docs.x.ai/developers/models before a long window.")
    if settings.key_ready:
        stdout.print("XAI_API_KEY is set. The value is not shown.")
    else:
        console.print("XAI_API_KEY is not set. `ciso-intel run` will stop until .env contains it.")
    stdout.print(f"Output directory: {options.out_dir.resolve()}")
    return 0


def _public_tool(item: dict) -> str:
    hidden = {"name", "servers"}
    parts = []
    for key, value in item.items():
        if key in hidden:
            continue
        if key == "collection_ids":
            parts.append(f"collections {len(value)}")
            continue
        parts.append(f"{key} {value}")
    if item["name"] == "mcp":
        hosts = ", ".join(server.get("server_url_host", "") for server in item.get("servers", []))
        parts.append(f"hosts {hosts}")
    return " \u00b7 ".join(parts)


def _doctor(settings, stdout: Console, console: Console) -> int:
    require_key(settings)
    from xai_sdk import Client

    stdout.print(f"Key is set. Host {settings.api_host}. Model requested: {settings.model}.")
    if settings.env_file:
        stdout.print(f"Env file: {settings.env_file}")
    else:
        stdout.print("Key came from the environment. No .env file was loaded.")
    try:
        client = Client(api_key=settings.api_key, api_host=settings.api_host, timeout=60)
        models = client.models.list_language_models()
    except Exception as exc:
        console.print(redact(f"Could not list models: {exc}", settings.api_key))
        return 1
    names = []
    for model in models:
        name = getattr(model, "name", None)
        if not name:
            descriptor = getattr(model, "DESCRIPTOR", None)
            name = getattr(model, "id", None)
            if descriptor is None and name is None:
                name = str(model)
        names.append(str(name))
    shown = ", ".join(names[:40])
    stdout.print("Language models: " + (shown or "(none returned)"))
    if settings.model not in names:
        console.print(
            f"{settings.model} was not in the listed names. The API may still accept it as an alias. "
            "SpaceXSI documents the flagship as grok-4.7."
        )
    else:
        stdout.print(f"{settings.model} is listed.")
    stdout.print(f"Reasoning effort for a run: {settings.effort}.")
    return 0


def _run(args, settings, stdout: Console, console: Console) -> int:
    require_key(settings)
    _ecosystems(args.ecosystems)
    now = datetime.now(DETROIT)
    window = _window_from_args(args, stdin=sys.stdin, stdout=sys.stderr, now=now, allow_prompt=True)
    options = _options(args, settings, window)

    def log(message: str) -> None:
        stdout.print(message)

    result = execute(settings, options, log)
    stdout.print("")
    stdout.print(f"Report {result.report_id}")
    stdout.print(f"Posture {result.posture}")
    stdout.print(f"Confirmed {result.finding_count}  \u00b7  excluded {result.omitted_count}")
    stdout.print(f"PDF  {result.pdf_path.resolve()}")
    stdout.print(f"JSON {result.json_path.resolve()}")
    stdout.print("Attach report.json to a Grok Bot. The bot should follow grok_bot.instructions and brief only from grok_bot.facts_from_sources.")
    return 0


def _verify(path: Path, stdout: Console, console: Console) -> int:
    brief = _load_brief(path)
    from ciso_intel.verify import HttpFetcher

    fetcher = HttpFetcher()
    failed = 0
    checked = 0
    for finding in brief.findings:
        for evidence in finding.evidence:
            checked += 1
            result = fetcher(evidence.url)
            if result.error or result.status != 200:
                failed += 1
                stdout.print(f"{finding.id}  drift  {evidence.url}  {result.error or result.status}")
            else:
                stdout.print(f"{finding.id}  still up  {evidence.host}")
    stdout.print(f"Checked {checked} confirmed URL(s). {failed} did not return HTTP 200 today. The original brief is unchanged.")
    return 0


def _render(path: Path, stdout: Console, console: Console) -> int:
    brief = _load_brief(path)
    payload = path.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    pdf_path = path.with_suffix(".pdf")
    render_pdf(brief, pdf_path, digest)
    pdf_path.chmod(0o600)
    stdout.print(f"Rebuilt {pdf_path.resolve()} from {path.name}. Claims were not re-checked.")
    return 0


def _load_brief(path: Path) -> Brief:
    if not path.is_file():
        raise ConfigError(f"Report not found: {path}")
    try:
        return Brief.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ConfigError(f"{path} is not a ciso-intel report: {exc}") from exc


if __name__ == "__main__":
    sys.exit(main())
