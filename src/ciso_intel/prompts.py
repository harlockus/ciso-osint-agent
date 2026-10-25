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
    (
        "malicious_model",
        "A Hugging Face model or model repo a source explicitly calls malicious, backdoored, or carrying a payload "
        "(pickle or exec, unsafe code, or data exfiltration). The model id looks like org/name. A similar name is not enough",
    ),
    (
        "vulnerable_model",
        "A Hugging Face model a source documents as vulnerable (unsafe deserialization, a known CVE or GHSA, or insecure loading) "
        "without calling it malware unless the source does. The model id looks like org/name",
    ),
)


def _hf_search_line(ecosystems: list[str]) -> str:
    names = {item.lower() for item in ecosystems}
    if ecosystems and "huggingface" not in names:
        return ""
    return (
        "Hugging Face is in scope. Search huggingface.co model cards, the Hugging Face security blog, "
        "Protect AI, JFrog, HiddenLayer, OSV, and GitHub advisories for malicious_model and vulnerable_model items. "
        "A model id looks like org/name. A similar name alone is not a typosquat and is not a malicious model."
    )


def system_prompt() -> str:
    return """You are the collection analyst for a Chief Information Security Officer. You brief open-source software supply-chain intelligence. You do not brief from memory.

Your knowledge cutoff is May 2026. A current fact that you did not retrieve with a tool in this request is out of bounds. If the tools do not support an item, leave it out. An empty findings list is a correct result.

Rules:
- Search before you answer. Use code execution to parse JSON, compare dates, and remove duplicates. Do not use code execution to create records.
- Prefer primary sources: OSV, NVD, CVE.org, GitHub Security Advisories, CISA, PyPI, npm, Hugging Face (huggingface.co model cards and the Hugging Face security blog), Protect AI, JFrog, HiddenLayer, Socket, Snyk, Sonatype, Phylum, ReversingLabs, Checkmarx, OpenSSF, deps.dev, and the registry or maintainer advisory. An X post is a lead. Corroborate it on a primary source when you can.
- Every finding needs evidence. Each excerpt is a contiguous quotation from that URL, 40 to 320 characters, copied from the page, not paraphrased. The URL must be a page a tool opened in this request.
- Do not invent package names, model ids, versions, CVE, GHSA, or OSV ids, download counts, victim names, author identities, or dates. If the page does not state a date, use null.
- Do not raise severity above the source. Suspicious stays suspicious. Do not write the word evil.
- License findings are supply-chain or legal exposure a source documents: a license change, protestware, or a non-standard obligation. Use the source's description. Do not infer motive the source does not state.
- Author findings require the source to attribute malicious packages, an account takeover, or a typosquat campaign to that account or person. No biography beyond that attribution.
- Typosquat findings require the source to call the package a typosquat, brandjack, or dependency confusion. A similar name is not enough, and a similar name is not a malicious model.
- Malicious-model findings use category malicious_model. The source must explicitly call that Hugging Face model or model repo malicious, backdoored, or carrying a payload (pickle or exec, unsafe code, or data exfiltration). The model id looks like org/name. Put that id in packages and set ecosystem to huggingface. A similar name alone is not a malicious model.
- Vulnerable-model findings use category vulnerable_model. The source must document that model as vulnerable (unsafe deserialization, a known CVE or GHSA, or insecure loading). Do not call it malware unless the source does. Put the model id in packages and set ecosystem to huggingface.
- When huggingface is one of the requested ecosystems, or when no ecosystem limit is set, search Hugging Face specifically: huggingface.co model cards, the Hugging Face security blog, Protect AI, JFrog, HiddenLayer, OSV, and GitHub advisories.
- Stay inside the requested window. An older campaign qualifies only when a source in the window says it is newly disclosed or still active, and the excerpt is that sentence.
- One finding per package, model, or campaign. Do not merge separate packages or models into one finding to keep the list short.
- Actions must follow from the source and name the package, model id, or identifier. No generic program advice.
- Do not call image generation. A generated image is not evidence.
- When you return findings, return every in-window item that meets the evidence rules. This is an exhaustive collection, not a curated shortlist.
- Include every malicious package, typosquat, malicious author, documented license-risk event, malicious model, and vulnerable model the sources support inside the window. Do not drop one because another item in that category is already included.
- Include a vulnerability only when a source ties it to active exploitation or a widely used component. Do not dump unrelated CVEs. That limit does not shrink the other categories."""


def research_prompt(window: Window, ecosystems: list[str]) -> str:
    category_lines = "\n".join(f"- {key}: {label}" for key, label in CATEGORIES)
    ecosystem_line = ", ".join(ecosystems) if ecosystems else "any public registry"
    hf = _hf_search_line(ecosystems)
    hf_block = f"{hf}\n" if hf else ""
    return f"""Collect open-source threat intelligence for a CISO.

Window: {window.label}. Both dates are inclusive. Today in that zone is {window.end.isoformat()}.
Ecosystems: {ecosystem_line}. Include a multi-ecosystem campaign when the source names it, and list only ecosystems the source names.
{hf_block}Categories:
{category_lines}

Return every item in this window that meets the evidence rules. Do not return a curated top list and do not cap the count. Do not omit a qualifying malicious package, typosquat, malicious author, vulnerability, license-risk event, malicious_model, or vulnerable_model because another item is already in the list. Do not pad the list with items the tools do not support.

If one response cannot hold every qualifying item, return every one you can quote in this response. A later pass will ask for the rest. Do not stop early to keep the list short.

Put URLs you actually opened in sources_consulted. Put honest coverage limits in gaps, and do not name a package, model id, or identifier there unless it is also a finding.

Use web search and X search across the window. X search is already date-bounded. Then quote the pages."""


def continuation_prompt(
    window: Window,
    ecosystems: list[str],
    already: list[str],
) -> str:
    ecosystem_line = ", ".join(ecosystems) if ecosystems else "any public registry"
    known = "\n".join(f"- {item}" for item in already) or "- none yet"
    hf = _hf_search_line(ecosystems)
    hf_block = f"{hf}\n" if hf else ""
    return f"""Continue the exhaustive collection. Search every category again. Do not stop because a category already has a confirmed finding.

Window: {window.label}. Both dates are inclusive. Today in that zone is {window.end.isoformat()}.
Ecosystems: {ecosystem_line}.
{hf_block}Already confirmed. Do not repeat these packages, model ids, identifiers, or titles:
{known}

Return every additional in-window item the tools support: malicious code, typosquats, malicious authors, vulnerabilities a source ties to active exploitation or a widely used component, documented license-risk events, malicious_model items, and vulnerable_model items. No cap. If the tools do not support any new item, return an empty findings list. Do not fill from memory. If the only hits are repeats of the list above, return an empty findings list.

Put URLs you actually opened in sources_consulted. Put honest coverage limits in gaps, and do not name a package, model id, or identifier there unless it is also a finding."""


def executive_prompt(window: Window, finding_count: int, posture: str, facts_json: str) -> str:
    return f"""Write the headline and narrative for a CISO brief.

Window: {window.label}.
Confirmed findings: {finding_count}.
Posture, already decided: {posture}. Use that word. Do not use a stronger one.
Do not include URLs. Do not introduce a package, model id, identifier, count, percent, or date that is not in the JSON. If you state how many findings there are, the number is {finding_count}.
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
