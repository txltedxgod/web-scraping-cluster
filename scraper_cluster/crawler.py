"""SSRF-safe HTML web crawler and metadata extractor built with httpx and stdlib HTMLParser."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
from collections import deque
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

_BLOCKED_HOSTS = frozenset({"localhost", "localhost.localdomain", "metadata.google.internal"})


class SSRFError(ValueError):
    """Raised when a target URL resolves to a forbidden or non-public network."""


class _MetadataHTMLParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_parts: list[str] = []
        self.h1_parts: list[str] = []
        self.text_parts: list[str] = []
        self.description: str | None = None
        self.links: list[str] = []
        self._in_title = False
        self._in_h1 = False
        self._ignored_depth = 0
        self._seen_links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if t in ("script", "style", "noscript"):
            self._ignored_depth += 1
        elif t == "title":
            self._in_title = True
        elif t == "h1":
            self._in_h1 = True
        elif t == "meta" and attr_map.get("name", "").lower() == "description":
            content = attr_map.get("content", "").strip()
            if content and not self.description:
                self.description = content
        elif t == "a" and attr_map.get("href"):
            resolved = urljoin(self.base_url, attr_map["href"].strip())
            parsed = urlparse(resolved)
            if parsed.scheme in ("http", "https"):
                clean_link = urlunparse(parsed._replace(fragment=""))
                if clean_link not in self._seen_links:
                    self._seen_links.add(clean_link)
                    self.links.append(clean_link)

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in ("script", "style", "noscript") and self._ignored_depth > 0:
            self._ignored_depth -= 1
        elif t == "title":
            self._in_title = False
        elif t == "h1":
            self._in_h1 = False

    def handle_data(self, data: str) -> None:
        if self._ignored_depth > 0:
            return
        stripped = " ".join(data.split())
        if not stripped:
            return
        if self._in_title:
            self.title_parts.append(stripped)
        if self._in_h1:
            self.h1_parts.append(stripped)
        self.text_parts.append(stripped)


def _is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_public_url(url: str, *, resolve_dns: bool = False) -> str:
    """Ensure the URL uses http(s) and does not point to private/internal networks."""
    cleaned = (url or "").strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise SSRFError(f"Unsupported or malformed URL scheme: {url!r}")

    host = (parsed.hostname or "").strip().lower()
    if not host or host in _BLOCKED_HOSTS or host.endswith((".local", ".internal")):
        raise SSRFError(f"Access to internal hostname {host!r} is forbidden.")

    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if _is_forbidden_ip(ip_obj):
            raise SSRFError(f"Access to non-public IP literal {host!r} is forbidden.")
    elif resolve_dns:
        try:
            infos = socket.getaddrinfo(host, parsed.port or 80, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise SSRFError(f"Failed to resolve host {host!r}: {exc}") from exc
        for info in infos:
            addr = info[4][0].split("%")[0]
            if _is_forbidden_ip(ipaddress.ip_address(addr)):
                raise SSRFError(f"Host {host!r} resolved to forbidden IP {addr!r}.")

    return urlunparse(parsed._replace(fragment=""))


class ScraperNode:
    """Distributed crawler worker executing SSRF-guarded HTTP scrapes and HTML parsing."""

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 10.0,
        resolve_dns: bool | None = None,
    ) -> None:
        self._transport = transport
        self._timeout = timeout
        # Enforce live DNS SSRF checks whenever executing real network traffic
        self._resolve_dns = (transport is None) if resolve_dns is None else resolve_dns

    @staticmethod
    def parse_html(html: str, base_url: str) -> dict[str, Any]:
        """Extract title, description, H1, outbound links, text length, and digest."""
        parser = _MetadataHTMLParser(base_url)
        parser.feed(html)
        parser.close()

        text = " ".join(parser.text_parts)
        content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        return {
            "extracted_title": " ".join(parser.title_parts) or None,
            "description": parser.description,
            "h1": " ".join(parser.h1_parts) or None,
            "text_length": len(text),
            "content_hash": content_hash,
            "links_found": len(parser.links),
            "links": parser.links,
        }

    def scrape_url(self, url: str) -> dict[str, Any]:
        """Validate URL for SSRF, fetch page content, and extract structured metadata."""
        safe_url = validate_public_url(url, resolve_dns=self._resolve_dns)
        client_kwargs: dict[str, Any] = {
            "timeout": self._timeout,
            "follow_redirects": False,
            "headers": {"User-Agent": "WebScraperCluster/1.0"},
        }
        if self._transport is not None:
            client_kwargs["transport"] = self._transport

        with httpx.Client(**client_kwargs) as client:
            response = client.get(safe_url)

        parsed_meta = self.parse_html(response.text, str(response.url))
        return {
            "target_url": safe_url,
            "status_code": response.status_code,
            **parsed_meta,
        }

    def crawl_batch(self, seed_urls: list[str], max_urls: int = 20) -> dict[str, Any]:
        """Deduplicate URL queue and scrape up to max_urls targets sequentially."""
        queue: deque[str] = deque()
        queued_set: set[str] = set()
        for raw in seed_urls:
            normalized = validate_public_url(raw, resolve_dns=self._resolve_dns)
            if normalized not in queued_set:
                queued_set.add(normalized)
                queue.append(normalized)

        results: list[dict[str, Any]] = []
        while queue and len(results) < max_urls:
            target = queue.popleft()
            results.append(self.scrape_url(target))
        return {"processed": len(results), "results": results}
