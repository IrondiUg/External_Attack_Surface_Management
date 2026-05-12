from settings import TARGET_DOMAIN
from subdomain_scanner import SubdomainScanner
from dns_resolver import DNSResolver
from http_prober    import HTTPProber
from s3_scanner   import S3Scanner
from nuclei_scanner    import NucleiScanner
import warnings
warnings.filterwarnings("ignore")  # suppress SSL warnings

def print_separator(title: str):
    print("\n" + "=" * 55)
    print(f"  {title}")
    print("=" * 55)

def run(target: str):
    print_separator(f"EASM Scan — {target}")
    # ── PHASE 1: DISCOVERY ──────────────────────────────────────
    # Subdomains
    print_separator("Phase 1a: Subdomain Discovery")
    scanner    = SubdomainScanner(target)
    raw_assets = scanner.scan()

    if not raw_assets:
        print("No subdomains found. Exiting.")
        return

    domains = [a["domain"] for a in raw_assets]

    # DNS Resolution
    print_separator("Phase 1b: DNS Resolution")
    resolver    = DNSResolver()
    dns_results = resolver.resolve_batch(domains)
    dns_map     = {r["domain"]: r for r in dns_results}

    # HTTP Enrichment
    print_separator("Phase 1c: HTTP Enrichment")
    live_domains = [d for d in domains if dns_map.get(d, {}).get("resolved")]
    print(f"{len(live_domains)} of {len(domains)} domains are resolvable")

    prober       = HTTPProber()
    http_results = prober.probe_batch(live_domains)
    http_map     = {r["domain"]: r for r in http_results}

    # S3 Bucket Scanning
    print_separator("Phase 1d: S3 Bucket Scanning")
    s3_scanner = S3Scanner(target)
    s3_findings = s3_scanner.scan()

    # ── PHASE 1 SUMMARY ─────────────────────────────────────────
    print_separator("Phase 1 Results")
    print(f"\n{'Domain':<40} {'IP':<16} {'Status':<8} {'Title':<35} {'Tech'}")
    print("-" * 110)
    for domain in domains:
        dns  = dns_map.get(domain, {})
        http = http_map.get(domain, {})
        ip   = dns.get("ip_addresses", ["-"])[0] if dns.get("ip_addresses") else "-"
        status = str(http.get("http_status", "-"))
        title  = (http.get("http_title") or "-")[:35]
        tech   = ", ".join(http.get("technologies", [])) or "-"
        print(f"{domain:<40} {ip:<16} {status:<8} {title:<35} {tech}")

    if s3_findings:
        print("\n--- S3 Bucket Findings ---")
        print(f"{'Bucket':<40} {'Public':<8} {'Listing':<10} {'Severity':<10} {'Files Found'}")
        print("-" * 95)
        for b in s3_findings:
            files = len(b["exposed_files"])
            print(f"{b['bucket_name']:<40} "
                  f"{'YES' if b['is_public'] else 'No':<8} "
                  f"{'YES' if b['allows_listing'] else 'No':<10} "
                  f"{b['severity']:<10} "
                  f"{files} file(s)")
            
            if b["exposed_files"]:
                for ef in b["exposed_files"][:10]:   # show first 10 files
                    print(f"  -> {ef}")
    else:
        print("\n[S3] No exposed buckets found.")


    # ── PHASE 2: VULNERABILITY SCANNING ─────────────────────────
    print_separator("Phase 2: Vulnerability Scanning (Nuclei)")
    nuclei = NucleiScanner()

    # Classify and scan subdomains — live first
    live_targets    = [f"https://{d}" for d in live_domains
                       if http_map.get(d, {}).get("http_status") in [200, 301, 302, 401, 403]]

    unknown_targets = [d for d in live_domains
                       if http_map.get(d, {}).get("http_status") not in [200, 301, 302, 401, 403]]

    dead_targets    = [d for d in domains if not dns_map.get(d, {}).get("resolved")]

    nuclei.scan(live_targets,    label="LIVE subdomains")
    nuclei.scan(unknown_targets, label="UNKNOWN subdomains")
    nuclei.scan(dead_targets,    label="DEAD subdomains")

    # Scan S3 bucket URLs through Nuclei too
    s3_urls = [b["url"] for b in s3_findings if b.get("url")]
    nuclei.scan(s3_urls, label="S3 buckets")

    # ── FINAL SUMMARY ───────────────────────────────────────────
    print_separator("Scan Complete")
    print(f"  Target:          {target}")
    print(f"  Subdomains:      {len(domains)}")
    print(f"  Live domains:    {len(live_targets)}")
    print(f"  S3 buckets:      {len(s3_findings)}")
    print(f"  Public buckets:  {sum(1 for b in s3_findings if b['is_public'])}")
    print("=" * 55)
    print("\nScan finished. Review results above.")

if __name__ == "__main__":
    run(TARGET_DOMAIN)