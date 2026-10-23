"""Grok 4.7 collection agent. Tools run on SpaceXSI; we keep the citations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from google.protobuf.json_format import MessageToDict
from pydantic import BaseModel, ValidationError

from ciso_intel.config import Settings, redact
from ciso_intel.schema import ExecutiveDraft, ResearchPacket
from ciso_intel.textutil import URL_RE, clean_url
from ciso_intel.tooling import ToolPlan, x_search_datetimes
from ciso_intel.window import Window

FENCE_RE = re.compile(r"^```[a-zA-Z0-9]*\s*|\s*```$", re.MULTILINE)


class IntelError(RuntimeError):
    pass


class ModelOutputError(IntelError):
    def __init__(self, content: str, detail: str) -> None:
        super().__init__("Model output did not match the evidence schema.")
        self.content = content
        self.detail = detail


@dataclass
class TurnMeta:
    label: str
    response_id: str
    citations: list[str]
    usage: dict
    cost_usd: float | None
    tool_usage: dict
    tool_log: list[dict] = field(default_factory=list)
    content: str = ""
    images_discarded: int = 0


@dataclass
class TurnResult:
    packet: ResearchPacket | ExecutiveDraft | None
    meta: TurnMeta


class GrokIntelAgent:
    def __init__(self, settings: Settings, log, *, api_key: str) -> None:
        from xai_sdk import Client

        self.settings = settings
        self.log = log
        self.api_key = api_key
        self.client = Client(api_key=api_key, api_host=settings.api_host, timeout=settings.timeout)

    def research(self, *, system: str, prompt: str, plan: ToolPlan, window: Window) -> TurnResult:
        return self._turn(
            label="research",
            system=system,
            prompt=prompt,
            plan=plan,
            window=window,
            shape=ResearchPacket,
            tools_on=True,
        )

    def research_gap(
        self,
        *,
        system: str,
        prompt: str,
        plan: ToolPlan,
        window: Window,
        label: str = "gap",
    ) -> TurnResult:
        return self._turn(
            label=label,
            system=system,
            prompt=prompt,
            plan=plan,
            window=window,
            shape=ResearchPacket,
            tools_on=True,
        )

    def executive(self, *, system: str, prompt: str) -> TurnResult:
        empty = ToolPlan(enabled=[], withheld=[], include=["inline_citations"])
        return self._turn(
            label="executive",
            system=system,
            prompt=prompt,
            plan=empty,
            window=None,
            shape=ExecutiveDraft,
            tools_on=False,
        )

    def _turn(self, *, label, system, prompt, plan: ToolPlan, window: Window | None, shape, tools_on: bool) -> TurnResult:
        from xai_sdk.chat import system as system_message
        from xai_sdk.chat import user as user_message

        self.log(f"{label}: {self.settings.model} reasoning {self.settings.effort}")
        chat = self.client.chat.create(
            model=self.settings.model,
            reasoning_effort=self.settings.effort,
            tools=self._sdk_tools(plan, window) if tools_on else None,
            response_format=shape,
            store_messages=False,
            use_encrypted_content=False,
            include=plan.include or None,
        )
        chat.append(system_message(system))
        chat.append(user_message(prompt))
        latest = None
        tool_log: list[dict] = []
        seen: set[tuple[str, str]] = set()
        last_tokens = 0
        try:
            for response, chunk in chat.stream():
                latest = response
                for call in chunk.tool_calls:
                    kind, detail = _describe_call(call)
                    key = (kind, detail[:120])
                    if key in seen:
                        continue
                    seen.add(key)
                    tool_log.append({"type": kind, "detail": detail[:500]})
                    self.log(f"  {kind}  {detail[:160]}")
                tokens = int(getattr(response.usage, "reasoning_tokens", 0) or 0)
                if tokens and tokens - last_tokens >= 4000:
                    last_tokens = tokens
                    self.log(f"  reasoning tokens {tokens}")
        except Exception as exc:
            raise IntelError(redact(f"SpaceXSI request failed during {label}: {_error_text(exc)}", self.api_key)) from exc
        if latest is None or not (latest.content or "").strip():
            raise ModelOutputError("", f"{label} returned no JSON.")
        content = latest.content
        images = len(getattr(latest, "image_outputs", []) or [])
        if images:
            self.log(f"  discarded {images} generated image(s); they are not evidence")
        try:
            parsed = _parse(content, shape)
        except (ValidationError, ValueError) as exc:
            raise ModelOutputError(content, redact(str(exc), self.api_key)) from exc
        meta = TurnMeta(
            label=label,
            response_id=str(getattr(latest, "id", "") or ""),
            citations=_citations(latest),
            usage=_usage(latest),
            cost_usd=getattr(latest, "cost_usd", None),
            tool_usage=dict(getattr(latest, "server_side_tool_usage", {}) or {}),
            tool_log=tool_log,
            content=content,
            images_discarded=images,
        )
        cost = meta.cost_usd
        if cost is not None:
            self.log(f"  {label} cost ${cost:.4f}")
        return TurnResult(packet=parsed, meta=meta)

    def _sdk_tools(self, plan: ToolPlan, window: Window | None):
        from xai_sdk.tools import code_execution, collections_search, image_generation, mcp, web_search, x_search

        if window is None:
            raise IntelError("Search tools need a collection window.")
        start, end = x_search_datetimes(window)
        tools = []
        for item in plan.enabled:
            name = item["name"]
            if name == "web_search":
                tools.append(
                    web_search(
                        enable_image_understanding=item["image_understanding"],
                        enable_image_search=item["image_search"],
                        user_location_timezone=item.get("user_location_timezone"),
                    )
                )
            elif name == "x_search":
                tools.append(
                    x_search(
                        from_date=start,
                        to_date=end,
                        enable_image_understanding=item["image_understanding"],
                        enable_video_understanding=item["video_understanding"],
                    )
                )
            elif name == "code_execution":
                tools.append(code_execution())
            elif name == "collections_search":
                tools.append(collections_search(collection_ids=item["collection_ids"]))
            elif name == "image_generation":
                tools.append(image_generation(action="generate"))
            elif name == "mcp":
                for server in self.settings.mcp_servers:
                    kwargs = {
                        "server_url": server["server_url"],
                        "server_label": server.get("server_label"),
                        "server_description": server.get("server_description"),
                    }
                    allowed = server.get("allowed_tool_names")
                    if allowed:
                        kwargs["allowed_tool_names"] = allowed
                    if server.get("authorization"):
                        kwargs["authorization"] = server["authorization"]
                    tools.append(mcp(**kwargs))
        return tools


def _parse(content: str, shape: type[BaseModel]):
    text = content.strip()
    text = FENCE_RE.sub("", text).strip()
    return shape.model_validate_json(text)


def _describe_call(call) -> tuple[str, str]:
    from xai_sdk.tools import get_tool_call_type

    kind = get_tool_call_type(call)
    function = getattr(call, "function", None)
    name = getattr(function, "name", "") if function is not None else ""
    arguments = getattr(function, "arguments", "") if function is not None else ""
    detail = " ".join(part for part in (name, arguments or "") if part)
    detail = re.sub(r"\s+", " ", detail).strip()
    return kind, detail


def _usage(response) -> dict:
    usage = getattr(response, "usage", None)
    if usage is None:
        return {}
    keys = (
        "prompt_tokens",
        "completion_tokens",
        "reasoning_tokens",
        "total_tokens",
        "cached_prompt_text_tokens",
        "prompt_text_tokens",
        "num_sources_used",
    )
    return {key: int(getattr(usage, key, 0) or 0) for key in keys}


def _citations(response) -> list[str]:
    found: list[str] = []
    for url in list(getattr(response, "citations", []) or []):
        found.append(str(url))
    try:
        for citation in getattr(response, "inline_citations", []) or []:
            found.extend(URL_RE.findall(json.dumps(MessageToDict(citation, preserving_proto_field_name=True))))
    except Exception:
        pass
    try:
        for output in getattr(response, "tool_outputs", []) or []:
            message = output.message
            found.extend(URL_RE.findall(message.content or ""))
            for call in message.tool_calls:
                found.extend(URL_RE.findall(json.dumps(MessageToDict(call, preserving_proto_field_name=True))))
    except Exception:
        pass
    found.extend(URL_RE.findall(getattr(response, "content", "") or ""))
    cleaned = []
    seen = set()
    for url in found:
        item = clean_url(url)
        if item and item not in seen:
            seen.add(item)
            cleaned.append(item)
    return cleaned


def _error_text(exc: Exception) -> str:
    detail = getattr(exc, "details", None)
    if callable(detail):
        try:
            text = detail()
        except Exception:
            text = None
        if text:
            return str(text)
    return str(exc)
