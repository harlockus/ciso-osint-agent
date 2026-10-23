"""Collection window in the CISO's time zone."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

DETROIT = ZoneInfo("America/Detroit")
MAX_LOOKBACK_DAYS = 90
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_DAYS_RE = re.compile(r"(\d+)\s*(?:d|days?)?\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class Window:
    start: date
    end: date
    timezone: str = "America/Detroit"

    @property
    def label(self) -> str:
        return f"{format_date(self.start)} through {format_date(self.end)} ({self.timezone})"

    def as_dict(self) -> dict:
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "inclusive": True,
            "timezone": self.timezone,
            "label": self.label,
        }


def format_date(value: date) -> str:
    return f"{value.day} {value.strftime('%B')} {value.year}"


class WindowChoiceError(ValueError):
    """The operator's time-frame text could not be used."""


def make_window(days: int, now: datetime) -> Window:
    if days < 1 or days > MAX_LOOKBACK_DAYS:
        raise ValueError(f"Lookback must be between 1 and {MAX_LOOKBACK_DAYS} days.")
    local = now.astimezone(DETROIT)
    end = local.date()
    return Window(start=end - timedelta(days=days), end=end)


def window_from_dates(start: date, end: date, *, today: date | None = None) -> Window:
    if end < start:
        raise WindowChoiceError("The start date must be on or before the end date.")
    if (end - start).days > MAX_LOOKBACK_DAYS:
        raise WindowChoiceError(f"The window cannot be longer than {MAX_LOOKBACK_DAYS} days.")
    if today is not None and end > today:
        raise WindowChoiceError("The end date cannot be after today in America/Detroit.")
    return Window(start=start, end=end)


def parse_window_choice(text: str, now: datetime, *, default_days: int = 14) -> Window:
    """Accept a lookback in days, or two inclusive YYYY-MM-DD dates."""
    cleaned = text.strip()
    today = now.astimezone(DETROIT).date()
    if not cleaned:
        return make_window(default_days, now)
    dates = _DATE_RE.findall(cleaned)
    if dates:
        if len(dates) != 2:
            raise WindowChoiceError("Provide both a start and an end date as YYYY-MM-DD, or a number of days.")
        try:
            start = date.fromisoformat(dates[0])
            end = date.fromisoformat(dates[1])
        except ValueError as exc:
            raise WindowChoiceError("Those dates are not valid YYYY-MM-DD values.") from exc
        return window_from_dates(start, end, today=today)
    match = _DAYS_RE.fullmatch(cleaned)
    if match is None:
        raise WindowChoiceError("Enter a number of days, or a start and end date as YYYY-MM-DD YYYY-MM-DD.")
    try:
        return make_window(int(match.group(1)), now)
    except ValueError as exc:
        raise WindowChoiceError(str(exc)) from exc


def prompt_for_window(stdin, stdout, now: datetime, *, suggested_days: int = 14) -> Window:
    """Ask for a window and wait for an explicit yes. Enter reviews the suggestion only."""
    suggestion = make_window(suggested_days, now)
    stdout.write(
        "Time frame for this brief. Dates are America/Detroit and inclusive.\n"
        "Enter a number of days, or a start and end date as YYYY-MM-DD YYYY-MM-DD.\n"
        f"Suggested: {suggested_days} days, {suggestion.label}.\n"
        "Press Enter to review that suggestion. The run does not start until you confirm.\n"
    )
    stdout.flush()
    while True:
        stdout.write("Window: ")
        stdout.flush()
        line = stdin.readline()
        if line == "":
            raise EOFError("No time frame was entered.")
        try:
            window = parse_window_choice(line, now, default_days=suggested_days)
        except WindowChoiceError as exc:
            stdout.write(f"{exc}\n")
            stdout.flush()
            continue
        stdout.write(f"Inclusive window: {window.label}.\n")
        stdout.write("Use this window? Type y to confirm: ")
        stdout.flush()
        answer = stdin.readline()
        if answer == "":
            raise EOFError("The window was not confirmed.")
        if answer.strip().lower() in {"y", "yes"}:
            stdout.write("\n")
            stdout.flush()
            return window
        stdout.write("Enter the time frame again.\n")
        stdout.flush()


def parse_date(value: str | None) -> date | None:
    if not value:
        return None
    text = value.strip()
    if len(text) >= 10 and text[4] == "-" and text[7] == "-":
        try:
            return date.fromisoformat(text[:10])
        except ValueError:
            return None
    return None
