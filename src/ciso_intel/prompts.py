"""Instructions that keep Grok inside retrieved sources."""

from __future__ import annotations

from ciso_intel.schema import FindingRecord
from ciso_intel.window import Window

CATEGORIES = (
    ("malicious_code", "Malicious code in a registry package or open-source project"),
    ("vulnerability", "A vulnerability a source ties to active exploitation or a widely used component"),
    ("malicious_author", "An account or person a source attributes to malicious packages, takeover, or a typosquat campaign"),
    ("license_risk", "A license change, protestware, or non-standard obligation a source documents"),
    ("typosquat", "A package a source explicitly calls a typosquat, brandjack, or dependency confusion"),
)


def system_prompt() -> str:
    return """You are the collection analyst for a Chief Information Security Officer. You brief open-source software supply-chain intelligence. You do not brief from memory.

Your knowledge cutoff is May 2026. A current fact that you did not retrieve with a tool in this request is out of bounds. If the tools do not support an item, leave it out. An empty findings list is a correct result.

Rules:
- Search before you answer. Use code execution to parse JSON, compare dates, and remove duplicates. Do not use code execution to create records.
- Prefer primary sources: OSV, NVD, CVE.org, GitHub Security Advisories, CISA, PyPI, npm, Socket, Snyk, Sonatype, Phylum, ReversingLabs, Checkmarx, OpenSSF, deps.dev, and the registry or maintainer advisory. An X post is a lead. Corroborate it on a primary source when you can.
- Every finding needs evidence. Each excerpt is a contiguous quotation from that URL, 40 to 320 characters, copied from the page, not paraphrased. The URL must be a page a tool opened in this request.
- Do not invent package names, versions, CVE, GHSA, or OSV ids, download counts, victim names, author identities, or dates. If the page does not state a date, use null.
- Do not raise severity above the source. Suspicious stays suspicious. Do not write the word evil.
- License findings are supply-chain or legal exposure a source documents: a license change, protestware, or a non-standard obligation. Use the source's description. Do not infer motive the source does not state.
- Author findings require the source to attribute malicious packages, an account takeover, or a typosquat campaign to that account or person. No biography beyond that attribution.
- Typosquat findings require the source to call the package a typosquat, brandjack, or dependency confusion. A similar name is not enough.
- Stay inside the requested window. An older campaign qualifies only when a source in the window says it is newly disclosed or still active, and the excerpt is that sentence.
- One finding per package or campaign. Do not merge separate packages into one finding to keep the list short.
- Actions must follow from the source and name the package or identifier. No generic program advice.
- Do not call image generation. A generated image is not evidence.
- When you return findings, return every in-window item that meets the evidence rules. This is an exhaustive collection, not a curated shortlist.
- Include every malicious package, typosquat, malicious author, and documented license-risk event the sources support inside the window. Do not drop one because another item in that category is already included.
- Include a vulnerability only when a source ties it to active exploitation or a widely used component. Do not dump unrelated CVEs. That limit does not shrink the other categories."""


def research_prompt(window: Window, ecosystems: list[str]) -> str:
    category_lines = "\n".join(f"- {key}: {label}" for key, label in CATEGORIES)
    ecosystem_line = ", ".join(ecosystems) if ecosystems else "any public registry"
    return f"""Collect open-source threat intelligence for a CISO.

Window: {window.label}. Both dates are inclusive. Today in that zone is {window.end.isoformat()}.
Ecosystems: {ecosystem_line}. Include a multi-ecosystem campaign when the source names it, and list only ecosystems the source names.

Categories:
{category_lines}

Return every item in this window that meets the evidence rules. Do not return a curated top list and do not cap the count. Do not omit a qualifying malicious package, typosquat, malicious author, vulnerability, or license-risk event because another item is already in the list. Do not pad the list with items the tools do not support.

If one response cannot hold every qualifying item, return every one you can quote in this response. A later pass will ask for the rest. Do not stop early to keep the list short.

Put URLs you actually opened in sources_consulted. Put honest coverage limits in gaps, and do not name a package or identifier there unless it is also a finding.

Use web search and X search across the window. X search is already date-bounded. Then quote the pages."""


def continuation_prompt(
    window: Window,
    ecosystems: list[str],
    already: list[str],
) -> str:
    ecosystem_line = ", ".join(ecosystems) if ecosystems else "any public registry"
    known = "\n".join(f"- {item}" for item in already) or "- none yet"
    return f"""Continue the exhaustive collection. Search every category again. Do not stop because a category already has a confirmed finding.

Window: {window.label}. Both dates are inclusive. Today in that zone is {window.end.isoformat()}.
Ecosystems: {ecosystem_line}.

Already confirmed. Do not repeat these packages, identifiers, or titles:
{known}

Return every additional in-window item the tools support: malicious code, typosquats, malicious authors, vulnerabilities a source ties to active exploitation or a widely used component, and documented license-risk events. No cap. If the tools do not support any new item, return an empty findings list. Do not fill from memory. If the only hits are repeats of the list above, return an empty findings list.

Put URLs you actually opened in sources_consulted. Put honest coverage limits in gaps, and do not name a package or identifier there unless it is also a finding."""


def executive_prompt(window: Window, finding_count: int, posture: str, facts_json: str) -> str:
    return f"""Write the headline and narrative for a CISO brief.

Window: {window.label}.
Confirmed findings: {finding_count}.
Posture, already decided: {posture}. Use that word. Do not use a stronger one.
Do not include URLs. Do not introduce a package, identifier, count, percent, or date that is not in the JSON. If you state how many findings there are, the number is {finding_count}.
80 to 150 words of narrative, plain prose, no bullet list. No all-clear.

Verified findings JSON:
{facts_json}"""


def facts_for_executive(findings: list[FindingRecord]) -> list[dict]:
    rows = []
    for finding in findings:
        quote = finding.evidence[0].excerpt if finding.evidence else ""
        rows.append(
            {
                "id": finding.id,
                "category": finding.category,
                "severity": finding.severity,
                "title": finding.title,
                "ecosystem": finding.ecosystem,
                "packages": finding.packages,
                "identifiers": finding.identifiers,
                "actors": finding.actors,
                "quotation": quote,
                "actions": finding.actions,
            }
        )
    return rows
