# CISO Intel

A Python collector that briefs a CISO on open-source supply-chain risk. It asks Grok 4.7, at the maximum reasoning effort SpaceXSI documents, to search the live web and X. It then throws away anything it cannot quote from a page it fetched itself.

The run writes two files:

- a leadership PDF
- `report.json`, with a `grok_bot` object you can attach to a Grok Bot

An empty brief is a real result. It is not an all-clear, and this program cannot see your lockfiles.

## What a finding has to survive

1. Grok cited the URL from a tool in that run (web search, X search, code execution, or a collection or MCP server you configured).
2. This program fetched the URL itself. Private, loopback, and link-local addresses are refused.
3. The excerpt is a verbatim passage on that page, at least 40 characters.
4. The package, identifier, or author is on that page.
5. A stated date has to fall inside the window. Undated pages can stay, at lower confidence.

Severity is capped from the words on the page. A social post that is not backed by a primary advisory site cannot be briefed as critical. Paraphrases and actions that introduce a new identifier, URL, or figure are dropped. The quotation stays.

Excluded candidates are counted in the PDF. Their titles stay in `audit.omitted` inside the JSON and are marked `do_not_brief`. The Grok Bot instructions say to ignore that log.

## Model and tools

Checked against the SpaceXSI docs (docs.x.ai) for this build:

| Choice | Value |
| --- | --- |
| Model | `grok-4.7` |
| Reasoning | `xhigh` (maximum on this model) |
| Knowledge cutoff | May 2026, so current events have to come from tools |
| Web search | On, including image understanding and image search |
| X search | On, date-bounded to the window, including image and video understanding |
| Code execution | On, for parsing and dates, not for inventing records |
| Collections search | On when `XAI_COLLECTION_IDS` is set |
| Remote MCP | On when `CISO_INTEL_MCP_CONFIG` points at an HTTPS server list |
| Image generation | Off. It fabricates pixels. `--image-generation` attaches it, and any image is discarded |

SDK: `xai-sdk` 1.20, gRPC chat, `reasoning_effort="xhigh"`, server-side tools, structured JSON. Citations are taken from the API response and from tool outputs.

## Setup

Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
chmod 600 .env
```

Put the key from the [xAI console](https://console.x.ai) in `.env`:

```bash
XAI_API_KEY=your_key_here
```

The key is read from `.env` or the environment. There is no `--api-key` flag, and the value is never written into the brief.

`.env` is gitignored. If it is group- or world-readable, `doctor` and `run` warn you.

## Run

```bash
ciso-intel plan
ciso-intel doctor
ciso-intel run
```

`plan` does not call the API. `doctor` lists language models and checks that the key works. `run` writes:

```text
reports/CISO-OSINT-YYYYMMDD-HHMM-xxxx/report.pdf
reports/CISO-OSINT-YYYYMMDD-HHMM-xxxx/report.json
reports/CISO-OSINT-YYYYMMDD-HHMM-xxxx/report.json.sha256
reports/CISO-OSINT-YYYYMMDD-HHMM-xxxx/raw/
```

`raw/` is the model output from before verification. Do not brief from it.

The clock is America/Detroit. A live `ciso-intel run` from a terminal asks for the time frame before it searches. Enter a number of days, or a start and end date (`YYYY-MM-DD YYYY-MM-DD`). It prints the inclusive window and waits for `y`. Pressing Enter only reviews the suggested 14-day window (or `CISO_INTEL_LOOKBACK_DAYS` when that is set). The run does not start on that suggestion by itself.

These skip the question:

- `--days 7` uses a lookback of 7 days ending today
- `--start 2026-10-01 --end 2026-10-23` uses those inclusive dates
- `--yes` uses `--days` or `--start`/`--end` when you passed them, otherwise the suggested lookback
- a run whose stdin is not a terminal, such as CI, uses the same default as `--yes`

`--days 14` means the start is today minus 14 days and the end is today, both inclusive. An explicit start and end can be a single day. The span cannot be longer than 90 days. X search's end date is the next day because that API treats the end as exclusive.

```bash
ciso-intel run
ciso-intel run --days 7 --ecosystems npm,pypi --out ./reports
ciso-intel run --start 2026-10-01 --end 2026-10-23 --yes
ciso-intel run --no-gap-fill
ciso-intel run --no-video --no-image-tools
```

Collection is exhaustive for the five categories below. The research prompt does not ask for a top-N list. After each verified batch, another pass searches every category again and excludes packages, identifiers, and titles that already confirmed. It does not stop because a category already has one hit. A pass that confirms nothing new stops the run. A safety ceiling of 4 passes also stops the run. The report audit records `collection_passes`, `collection_pass_ceiling`, `collection_stop`, `collection_truncated`, and `collection_note`, so a run that hits the ceiling is visible in the JSON and in the PDF method section. `--no-gap-fill` keeps a single pass.

Other commands:

```bash
ciso-intel schema
ciso-intel verify reports/CISO-OSINT-.../report.json
ciso-intel render reports/CISO-OSINT-.../report.json
```

`verify` re-fetches confirmed URLs and does not rewrite the brief. `render` rebuilds the PDF and does not re-check claims.

## Grok Bot

Attach `report.json` and tell the bot to follow `grok_bot.instructions`.

The object matches the split SpaceXSI describes for consequential bot work: facts from sources, inferences, actions already completed, actions waiting for approval, and unresolved questions. Facts are the quotations. Inferences are paraphrases and lose when they disagree with the quotation. `actions_completed` only records that this run searched and fetched. It changed no registry and no production system.

`ciso-intel schema` prints the instruction paragraph on its own.

## Cost

`grok-4.7` at `xhigh` with web search and X search is a paid call. X search is billed per posts and profiles fetched, on top of tokens. A full collection can make up to 4 research calls, then one call for the executive prose. Confirm current prices at [Models](https://docs.x.ai/developers/models) and the [tool pages](https://docs.x.ai/developers/tools/overview) before you widen the window. The brief records the cost the API reports when it reports one.

## Categories

- Malicious code
- Vulnerabilities a source ties to active exploitation or a widely used component, not every new CVE
- Authors a source attributes to malicious packages, an account takeover, or a typosquat campaign
- License risk: a documented license change, protestware, or non-standard obligation
- Typosquats a source explicitly names

License findings use the source's description. The brief does not grade a license as evil.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The tests do not call the API and do not ship a sample threat report. A sample of current vulnerabilities would be a fabrication.

## Limits

- Knowledge inside the model stops at May 2026. If the tools do not retrieve it, it is not in the brief.
- Sites that block the fetcher, and scanned PDFs, drop the candidate. There is no OCR step.
- This is not a scan of your environment.

## License

MIT. See [LICENSE](LICENSE).
