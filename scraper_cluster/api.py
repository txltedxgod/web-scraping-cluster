from fastapi import FastAPI
from scraper_cluster.crawler import ScraperNode

app = FastAPI(title="Web Scraping Cluster", version="0.1.0")
node = ScraperNode()

@app.get("/api/v1/scrape")
def scrape(url: str):
    return node.scrape_url(url)
