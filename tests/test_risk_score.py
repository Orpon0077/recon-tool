from app.prioritization.risk_score import calculate_risk


def test_calculate_risk_handles_crawl_endpoint_dicts():
    scan_results = {
        "ssl": {"days_left": 10},
        "security_headers": {"score": 40},
        "ports": {"open_ports": [{"port": 22, "service": "SSH"}]},
        "firewall": {"detected": False},
        "subdomains": {"subdomains": ["a.example.com", "b.example.com"]},
        "osint": {"crt_subdomains": ["c.example.com"], "wayback_urls": []},
        "crawl": {
            "endpoints": [
                {"url": "https://example.com/admin", "status_code": 200},
                {"url": "https://example.com/login", "status_code": 200},
            ]
        },
    }

    result = calculate_risk(scan_results)

    assert result["overall_risk"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert result["score"] >= 0
    assert result["score"] <= 100
    assert result["total_findings"] >= 1
    assert result["headline"]


def test_cdn_is_observation_not_finding():
    result = calculate_risk({
        "security_headers": {"score": 90},
        "firewall": {
            "detected": True,
            "firewall_name": "CloudFront",
            "cdn_detected": True,
            "waf_detected": False,
            "cdn_name": "CloudFront",
        },
        "subdomains": {"subdomains": []},
    })

    assert result["total_findings"] == 0
    assert any("CDN detected" in obs["description"] for obs in result["observations"])


def test_sensitive_subdomain_flag_is_used():
    result = calculate_risk({
        "security_headers": {"score": 90},
        "firewall": {"detected": True, "cdn_detected": True, "waf_detected": False},
        "subdomains": {
            "subdomains": [
                {"subdomain": "api.example.com", "sensitive": True},
                {"subdomain": "db-backup-api.example.com", "sensitive": True},
            ]
        },
    })

    assert any("Sensitive subdomains" in finding["description"] for finding in result["findings"])
