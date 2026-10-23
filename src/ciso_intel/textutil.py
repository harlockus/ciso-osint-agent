"""Text, URL, and claim checks used to keep the brief source-bound."""

from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata
from urllib.parse import parse_qsl, urlencode, urlparse

PRIMARY_HOSTS = (
    "osv.dev",
    "nvd.nist.gov",
    "cve.org",
    "cisa.gov",
    "github.com",
    "githubusercontent.com",
    "github.blog",
    "pypi.org",
    "python.org",
    "npmjs.com",
    "npmjs.org",
    "socket.dev",
    "snyk.io",
    "sonatype.com",
    "sonatype.org",
    "phylum.io",
    "reversinglabs.com",
    "checkmarx.com",
    "openssf.org",
    "deps.dev",
    "rubygems.org",
    "crates.io",
    "pkg.go.dev",
    "go.dev",
    "golang.org",
    "packagist.org",
    "getcomposer.org",
    "nuget.org",
    "msrc.microsoft.com",
    "microsoft.com",
    "blog.google",
    "apache.org",
    "openssl.org",
    "kernel.org",
    "mitre.org",
    "first.org",
)

SOCIAL_HOSTS = ("x.com", "twitter.com", "mobile.x.com", "mobile.twitter.com")

SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")

ID_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[A-Za-z0-9]{4}){3}|PYSEC-\d{4}-\d+|MAL-\d{4}-\d+|OSV-\d{4}-\d+)\b",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")
SCOPED_RE = re.compile(r"@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
STATUS_RE = re.compile(r"/status(?:es)?/(\d+)")
PERCENT_RE = re.compile(r"\b\d+(?:\.\d+)?%")

CRITICAL_TERMS = (
    "malicious",
    "malware",
    "backdoor",
    "credential",
    "actively exploited",
    "known exploited",
    "worm",
    "ransomware",
    "remote code execution",
    "supply-chain attack",
    "supply chain attack",
    "trojan",
)
HIGH_TERMS = CRITICAL_TERMS + (
    "high severity",
    "vulnerability",
    "cve-",
    "typosquat",
    "typo-squat",
    "account takeover",
    "protestware",
    "compromised",
)


def norm(value: str) -> str:
    text = unicodedata.normalize("NFKC", value or "")
    text = text.translate(
        str.maketrans(
            {
                "\u00a0": " ",
                "\u2018": "'",
                "\u2019": "'",
                "\u201c": '"',
                "\u201d": '"',
                "\u2013": "-",
                "\u2014": "-",
                "\u00ad": "",
            }
        )
    )
    return re.sub(r"\s+", " ", text).strip().lower()


def clean_token(value: str) -> str:
    return value.strip().strip("`\"'.,;:()[]<>")


def clean_url(value: str) -> str:
    url = value.strip().strip("<>\"'")
    while url and url[-1] in ".,;":
        url = url[:-1]
    if url.endswith(")") and "(" not in url:
        url = url[:-1]
    return url


def host_of(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return ""
    return host.lower().removeprefix("www.")


def is_primary(host: str) -> bool:
    return any(host == item or host.endswith("." + item) for item in PRIMARY_HOSTS)


def is_social(host: str) -> bool:
    return any(host == item or host.endswith("." + item) for item in SOCIAL_HOSTS)


def url_key(url: str) -> str:
    try:
        parsed = urlparse(clean_url(url))
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower().removeprefix("www.")
    if not host:
        return ""
    path = (parsed.path or "/").rstrip("/") or "/"
    query = urlencode(
        [(key, item) for key, item in parse_qsl(parsed.query, keep_blank_values=True) if not key.lower().startswith("utm_")]
    )
    return f"{host}{path}" + (f"?{query}" if query else "")


def classify_url(url: str) -> str:
    """Return ``ok`` or a reason the URL must not be fetched."""
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return "bad_url"
    if parsed.scheme not in {"http", "https"}:
        return "bad_scheme"
    if parsed.username or parsed.password:
        return "embedded_credentials"
    host = parsed.hostname
    if not host:
        return "bad_host"
    host = host.lower().rstrip(".")
    if parsed.port not in {None, 80, 443}:
        return "bad_port"
    if host in {"localhost", "metadata.google.internal"} or host.endswith((".local", ".internal", ".localhost")):
        return "blocked_non_public"
    if host.isdigit():
        try:
            address = ipaddress.ip_address(int(host))
        except (ValueError, OSError):
            return "blocked_non_public"
        return "ok" if address.is_global else "blocked_non_public"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        return "ok" if address.is_global else "blocked_non_public"
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(5)
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return "dns_failed"
    finally:
        socket.setdefaulttimeout(previous)
    for info in infos:
        try:
            resolved = ipaddress.ip_address(info[4][0])
        except ValueError:
            return "blocked_non_public"
        if not resolved.is_global:
            return "blocked_non_public"
    return "ok"


def needle_in(needle: str, page_norm: str) -> bool:
    token = norm(needle)
    if len(token) < 4:
        return False
    return re.search(rf"(?<![a-z0-9_@./-]){re.escape(token)}(?![a-z0-9_-])", page_norm) is not None


def excerpt_in_page(excerpt: str, page: str) -> bool:
    left = norm(excerpt)
    right = norm(page)
    if len(left) < 40:
        return False
    return left in right


def find_ids(text: str) -> set[str]:
    return {match.group(0).upper() for match in ID_RE.finditer(text or "")}


def severity_cap_from_page(page: str) -> str:
    folded = norm(page)
    if any(term in folded for term in CRITICAL_TERMS):
        return "critical"
    if any(term in folded for term in HIGH_TERMS):
        return "high"
    return "medium"


def stricter_severity(left: str, right: str) -> str:
    return left if SEVERITY_ORDER.index(left) <= SEVERITY_ORDER.index(right) else right


def normalize_severity(value: str) -> str:
    folded = (value or "").strip().lower().replace("-", " ").replace("_", " ")
    aliases = {
        "critical": "critical",
        "crit": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "informational": "informational",
        "info": "informational",
    }
    return aliases.get(folded, "informational")


def prose_supported(text: str, corpus: str, *, allow_urls: bool = False) -> bool:
    """True when the text introduces no identifier, URL, scoped name, percent, or long number outside the corpus."""
    if not text or not text.strip():
        return False
    corpus_norm = corpus or ""
    corpus_ids = find_ids(corpus_norm)
    if not find_ids(text) <= corpus_ids:
        return False
    urls = [clean_url(match) for match in URL_RE.findall(text)]
    if urls and not allow_urls:
        return False
    corpus_keys = {url_key(match) for match in URL_RE.findall(corpus_norm)}
    if any(url_key(url) not in corpus_keys for url in urls):
        return False
    corpus_folded = norm(corpus_norm)
    for scoped in SCOPED_RE.findall(text):
        if norm(scoped) not in corpus_folded:
            return False
    stripped = text
    for identifier in corpus_ids:
        stripped = re.sub(re.escape(identifier), " ", stripped, flags=re.IGNORECASE)
    corpus_numbers = set(re.findall(r"\d{3,}", corpus_norm))
    if any(number not in corpus_numbers for number in re.findall(r"\d{3,}", stripped)):
        return False
    if any(percent not in corpus_norm for percent in PERCENT_RE.findall(text)):
        return False
    return True


def mismatches_posture(text: str, posture: str) -> bool:
    expected = {"severe": "severe", "elevated": "elevated", "guarded": "guarded"}.get(posture)
    if expected is None:
        return False
    folded = norm(text)
    named = [word for word in ("severe", "elevated", "guarded") if re.search(rf"\b{word}\b", folded)]
    return any(word != expected for word in named)


def overclaims(text: str, severities: set[str], posture: str) -> bool:
    folded = norm(text)
    if "critical" not in severities and re.search(r"(?<!non-)(?<!non )\bcritical\b", folded):
        return True
    if not ({"critical", "high"} & severities) and re.search(r"\bhigh[\s-]severity\b", folded):
        return True
    if posture == "guarded" and re.search(r"\b(severe|elevated)\b", folded):
        return True
    if posture == "elevated" and re.search(r"\bsevere\b", folded):
        return True
    if re.search(r"\ball[\s-]clear\b", folded):
        return True
    return False
