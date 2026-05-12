import requests
import re

TECH_SIGNATURES = {
    "WordPress":  ["wp-content", "wp-includes"],
    "Nginx":      ["nginx"],
    "Apache":     ["Apache"],
    "Cloudflare": ["cloudflare", "__cfduid"],
    "AWS S3":     ["AmazonS3", "s3.amazonaws.com"],
    "React":      ["react", "ReactDOM"],
    "Django":     ["csrfmiddlewaretoken"],
    "Laravel":    ["laravel_session"],
    "Jenkins":    ["Jenkins", "hudson"],
    "Grafana":    ["Grafana"],
}

class HTTPProber:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; EASM-Scanner/1.0)"
        })

    def probe(self, domain: str) -> dict:
        result = {
            "domain":       domain,
            "http_status":  None,
            "http_title":   None,
            "technologies": [],
            "final_url":    None,
            "reachable":    False,
            "error":        None
        }

        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}"
            try:
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                result["http_status"]  = resp.status_code
                result["final_url"]    = resp.url
                result["http_title"]   = self._extract_title(resp.text)
                result["technologies"] = self._detect_tech(resp)
                result["reachable"]    = True
                break

            except requests.exceptions.SSLError:
                continue

            except requests.exceptions.ConnectionError:
                continue

            except requests.exceptions.Timeout:
                result["error"] = "TIMEOUT"
                break

            except Exception as e:
                result["error"] = str(e)
                break

        return result

    def _extract_title(self, html: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:200]
        return ""

    def _detect_tech(self, response) -> list[str]:
        detected = []
        combined = response.text + str(response.headers).lower()
        for tech, signatures in TECH_SIGNATURES.items():
            if any(sig.lower() in combined.lower() for sig in signatures):
                detected.append(tech)
        return detected

    def probe_batch(self, domains: list[str]) -> list[dict]:
        results = []
        total   = len(domains)
        for i, domain in enumerate(domains, 1):
            r        = self.probe(domain)
            tech_str = ", ".join(r["technologies"]) or "unknown"
            status   = str(r["http_status"]) if r["http_status"] else "unreachable"
            title    = (r["http_title"] or "")[:40]
            print(f"  [{i}/{total}] {domain} -> {status} | {title} | {tech_str}")
            results.append(r)
        return results