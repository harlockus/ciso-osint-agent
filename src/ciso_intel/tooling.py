"""Which SpaceXSI tools a run attaches, and which it refuses to attach."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ciso_intel.window import Window


@dataclass(frozen=True)
class ToolPlan:
    enabled: list[dict]
    withheld: list[dict]
    include: list[str]

    @property
    def names(self) -> list[str]:
        return [item["name"] for item in self.enabled]


def build_tool_plan(
    *,
    window: Window,
    collection_ids: list[str],
    mcp_servers: list[dict],
    image_understanding: bool,
    image_search: bool,
    video_understanding: bool,
    image_generation: bool,
) -> ToolPlan:
    end_exclusive = window.end + timedelta(days=1)
    enabled: list[dict] = [
        {
            "name": "web_search",
            "image_understanding": image_understanding,
            "image_search": image_search,
            "user_location_timezone": "America/Detroit",
        },
        {
            "name": "x_search",
            "from_date": window.start.isoformat(),
            "to_date_exclusive": end_exclusive.isoformat(),
            "image_understanding": image_understanding,
            "video_understanding": video_understanding,
        },
        {"name": "code_execution"},
    ]
    include = [
        "inline_citations",
        "verbose_streaming",
        "web_search_call_output",
        "x_search_call_output",
        "code_execution_call_output",
    ]
    withheld: list[dict] = []
    if collection_ids:
        enabled.append({"name": "collections_search", "collection_ids": list(collection_ids)})
        include.append("collections_search_call_output")
    else:
        withheld.append(
            {
                "name": "collections_search",
                "reason": "Not configured. Set XAI_COLLECTION_IDS to search documents you uploaded to SpaceXSI.",
            }
        )
    if mcp_servers:
        enabled.append(
            {
                "name": "mcp",
                "servers": [
                    {
                        "server_label": item.get("server_label") or "",
                        "server_url_host": _host(item.get("server_url", "")),
                    }
                    for item in mcp_servers
                ],
            }
        )
        include.append("mcp_call_output")
    else:
        withheld.append(
            {
                "name": "mcp",
                "reason": "Not configured. Set CISO_INTEL_MCP_CONFIG to an HTTPS MCP server list.",
            }
        )
    if image_generation:
        enabled.append({"name": "image_generation", "action": "generate"})
    else:
        withheld.append(
            {
                "name": "image_generation",
                "reason": (
                    "Withheld. The image tool fabricates pixels. This brief does not present generated images as intelligence."
                ),
            }
        )
    return ToolPlan(enabled=enabled, withheld=withheld, include=include)


def x_search_datetimes(window: Window) -> tuple[datetime, datetime]:
    start = datetime(window.start.year, window.start.month, window.start.day, tzinfo=timezone.utc)
    end = datetime(window.end.year, window.end.month, window.end.day, tzinfo=timezone.utc) + timedelta(days=1)
    return start, end


def _host(url: str) -> str:
    from urllib.parse import urlparse

    return (urlparse(url).hostname or "").lower()
