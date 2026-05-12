import dns.resolver
import dns.exception

class DNSResolver:
    def __init__(self, timeout: int = 5):
        self.resolver          = dns.resolver.Resolver()
        self.resolver.timeout  = timeout
        self.resolver.lifetime = timeout

    def resolve(self, domain: str) -> dict:
        result = {
            "domain":       domain,
            "ip_addresses": [],
            "resolved":     False,
            "cname":        None,
            "error":        None
        }

        try:
            answers = self.resolver.resolve(domain, "A")
            result["ip_addresses"] = [str(r) for r in answers]
            result["resolved"]     = True

        except dns.resolver.NXDOMAIN:
            result["error"] = "NXDOMAIN"

        except dns.resolver.NoAnswer:
            try:
                cname = self.resolver.resolve(domain, "CNAME")
                result["cname"]    = str(cname[0].target)
                result["resolved"] = True
            except Exception:
                result["error"] = "NO_ANSWER"

        except dns.exception.Timeout:
            result["error"] = "TIMEOUT"

        except Exception as e:
            result["error"] = str(e)

        return result


    def resolve_batch(self, domains: list[str]) -> list[dict]:
        results = []
        total   = len(domains)
        for i, domain in enumerate(domains, 1):
            r      = self.resolve(domain)
            status = "OK" if r["resolved"] else "FAIL"
            ips    = ", ".join(r["ip_addresses"]) or r.get("error", "?")
            print(f"  [{i}/{total}] [{status}] {domain} -> {ips}")
            results.append(r)
        return results
