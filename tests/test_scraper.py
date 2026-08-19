from scraper_cluster.crawler import ScraperNode

def test_crawler():
    n = ScraperNode()
    res = n.scrape_url("https://example.com")
    assert res["status_code"] == 200
