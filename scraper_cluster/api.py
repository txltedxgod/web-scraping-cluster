"""FastAPI service exposing SSRF-safe scraping and deduplicated batch crawl routes."""

from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from scraper_cluster.crawler import ScraperNode, SSRFError

app = FastAPI(title="Web Scraping Cluster", version="1.0.0")
node = ScraperNode()


class CrawlBatchReq(BaseModel):
    """Deduplicated batch scrape request payload."""

    urls: list[str] = Field(..., min_length=1, max_length=25)
    max_urls: int = Field(default=20, ge=1, le=25)


@app.get("/health", tags=["Monitoring"])
def health() -> dict[str, str]:
    """Liveness check endpoint."""
    return {"status": "healthy"}


@app.get("/api/v1/scrape", tags=["Crawler"])
def scrape(url: str = Query(..., min_length=8, max_length=2048)) -> dict[str, Any]:
    """Validate and scrape a single public HTTP(S) target URL."""
    try:
        return node.scrape_url(url)
    except SSRFError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream fetch failed: {exc}") from exc


@app.post("/api/v1/crawl/batch", tags=["Crawler"])
def crawl_batch(req: CrawlBatchReq) -> dict[str, Any]:
    """Validate and crawl a deduplicated batch of public URLs."""
    try:
        return node.crawl_batch(req.urls, max_urls=req.max_urls)
    except SSRFError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream fetch failed: {exc}") from exc
