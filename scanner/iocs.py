"""Static IOC extraction. Nothing extracted here is ever contacted.

All values are labelled ``UNVERIFIED STATIC IOC``: strings in source code
are frequently benign (documentation links, library URLs...).
"""

from __future__ import annotations

import ipaddress
import re

_URL = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>()\\`]{3,300}", re.I)
_DOMAIN = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|ru|cn|su|xyz|top|"
    r"io|me|tk|ml|ga|cf|gq|pw|cc|ws|site|online|club|live|shop|app|dev|co|in|ir|tr|ua|de|uk|br|"
    r"id|vn|pl|nl|fr|us))\b", re.I)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}(?![\w:])", re.I)
_EMAIL = re.compile(r"\b[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b", re.I)
_SUSP_PATH = re.compile(
    r"(?:/tmp|/var/tmp|/dev/shm)/[\w./-]{1,120}|/etc/(?:passwd|shadow|cron\.d/[\w.-]+|crontab)|"
    r"/proc/self/environ|\.ssh/authorized_keys|/var/spool/cron[\w/.-]*|/etc/systemd/system/[\w.@-]+",
    re.I)


def _valid_ipv4(s: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(s)
    except ValueError:
        return False
    return not (ip.is_unspecified or ip.is_loopback or s.startswith("255.") or s.endswith(".0.0"))


def _valid_ipv6(s: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(s)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified)


def _ignored(domain: str, ignore: list[str]) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == i or d.endswith("." + i) for i in ignore)


def extract_iocs(text: str, ignore_domains: list[str] | None = None,
                 max_per_type: int = 50) -> dict[str, list[str]]:
    """Extract URLs, domains, IPs, e-mails and suspicious paths from *text*."""
    ignore = [d.lower() for d in (ignore_domains or [])]
    out: dict[str, list[str]] = {}

    def add(kind: str, value: str) -> None:
        bucket = out.setdefault(kind, [])
        if value not in bucket and len(bucket) < max_per_type:
            bucket.append(value)

    urls = []
    for m in _URL.finditer(text):
        url = m.group(0).rstrip(".,;:'\"")
        host = re.sub(r"^[a-z]+://", "", url, flags=re.I).split("/")[0].split(":")[0].split("@")[-1]
        if _ignored(host, ignore):
            continue
        urls.append(url)
        add("urls", url)
    for m in _DOMAIN.finditer(text):
        d = m.group(1).lower()
        if _ignored(d, ignore) or re.fullmatch(r"[\d.]+", d):
            continue
        # Skip things that look like PHP/JS member chains (e.g. "this.value.in")
        if d.count(".") > 5:
            continue
        add("domains", d)
    for m in _IPV4.finditer(text):
        if _valid_ipv4(m.group(0)):
            add("ipv4", m.group(0))
    for m in _IPV6.finditer(text):
        if m.group(0).count(":") >= 2 and _valid_ipv6(m.group(0)):
            add("ipv6", m.group(0))
    for m in _EMAIL.finditer(text):
        dom = m.group(0).split("@", 1)[1]
        if not _ignored(dom, ignore):
            add("emails", m.group(0))
    for m in _SUSP_PATH.finditer(text):
        add("suspicious_paths", m.group(0))
    return {k: v for k, v in out.items() if v}
