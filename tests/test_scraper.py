"""Unit and API tests for HTML extraction, SSRF blocking, and batch deduplication."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from scraper_cluster import api as scraper_api
from scraper_cluster.crawler import ScraperNode, SSRFError


def _mock_transport(pages: dict[str, str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        body = pages.get(str(request.url))
        if body is None:
            return httpx.Response(404, text="Not Found", request=request)
        return httpx.Response(
            200,
            text=body,
            headers={"content-type": "text/html"},
            request=request,
        )

    return httpx.MockTransport(handler)


def test_crawler_extracts_html_metadata_and_strips_scripts() -> None:
    html = """
    <html>
      <head>
        <title>Distributed Systems Hub</title>
        <meta name="description" content="Production crawler telemetry">
        <style>.hidden { display: none; }</style>
        <script>console.log("ignore script text");</script>
      </head>
      <body>
        <h1>Architecture Overview</h1>
        <p>Fast SSRF-safe scraping node.</p>
        <a href="/docs">Docs</a>
        <a href="https://example.com/docs#top">Duplicate fragment link</a>
      </body>
    </html>
    """
    node = ScraperNode(transport=_mock_transport({"https://example.com/": html}))
    res = node.scrape_url("https://example.com/")
    assert res["status_code"] == 200
    assert res["extracted_title"] == "Distributed Systems Hub"
    assert res["description"] == "Production crawler telemetry"
    assert res["h1"] == "Architecture Overview"
    assert res["links"] == ["https://example.com/docs"]
    assert res["text_length"] > 0


def test_ssrf_blocks_loopback_metadata_and_bad_schemes() -> None:
    node = ScraperNode(transport=_mock_transport({}))
    for bad in (
        "http://127.0.0.1:8000/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/health",
        "http://10.0.0.5/internal",
        "file:///etc/passwd",
    ):
        with pytest.raises(SSRFError):
            node.scrape_url(bad)


def test_crawl_batch_deduplicates_and_api_blocks_ssrf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _mock_transport(
        {"https://example.com/a": "<html><title>Page A</title><body>Hello</body></html>"}
    )
    fake_node = ScraperNode(transport=transport)
    batch = fake_node.crawl_batch(
        ["https://example.com/a#sec1", "https://example.com/a#sec2"]
    )
    assert batch["processed"] == 1
    assert batch["results"][0]["extracted_title"] == "Page A"

    monkeypatch.setattr(scraper_api, "node", fake_node)
    client = TestClient(scraper_api.app)
    assert client.get("/health").json() == {"status": "healthy"}
    assert client.get("/api/v1/scrape?url=http://169.254.169.254/").status_code == 403
    ok = client.get("/api/v1/scrape?url=https://example.com/a")
    assert ok.status_code == 200
    assert ok.json()["extracted_title"] == "Page A"
