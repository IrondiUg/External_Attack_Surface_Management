import subprocess
import json

class SubdomainScanner:
    def __init__(self, target: str):
        self.target = target

    def run_subfinder(self) -> list[dict]:
        print(f"[Subfinder] Scanning {self.target}...")
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.target, "-silent", "-json"],
                capture_output=True, text=True, timeout=120
            )

            subdomains = []
            for line in result.stdout.strip().splitlines():
                if line:
                    try:
                        subdomains.append(json.loads(line))

                    except json.JSONDecodeError:
                        subdomains.append({"host": line.strip(), "source": "subfinder"})

            return subdomains

        except FileNotFoundError:
            print("[Subfinder] ERROR: subfinder not installed.")
            print("  Run: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            return []

        except subprocess.TimeoutExpired:
            print("[Subfinder] WARNING: Timed out.")
            return []

    def scan(self) -> list[dict]:
        raw  = self.run_subfinder()
        seen = set()
        unique = []

        for item in raw:
            host = item.get("host", "").lower().strip()
            if host and host not in seen:
                seen.add(host)
                unique.append({
                    "domain": host,
                    "source": item.get("source", "subfinder")
                })

        print(f"[Subfinder] Found {len(unique)} unique subdomains")
        return unique