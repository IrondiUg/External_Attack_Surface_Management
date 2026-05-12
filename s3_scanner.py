import requests
import xml.etree.ElementTree as ET
from settings import COMPANY_NAME, S3_SUFFIXES, S3_TIMEOUT

S3_NAMESPACE = "{http://s3.amazonaws.com/doc/2006-03-01/}"

SENSITIVE_PATTERNS = [
    ".env", ".sql", ".db", ".bak", ".backup",
    "password", "secret", "credential", "private",
    "config", "database", "dump", ".pem", ".key",
    "access_key", "token", "auth", "id_rsa"
]

class S3Scanner:
    def __init__(self, target: str):
        self.target  = target
        self.company = COMPANY_NAME
        self.http    = requests.Session()
        self.http.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; EASM-Scanner/1.0)"
        })

    def _generate_permutations(self) -> list[str]:
        bases = [
            self.company.lower(),
            self.company.lower().replace(" ", "-"),
            self.company.lower().replace(" ", ""),
            self.target.replace(".", "-"),
            self.target.split(".")[0],
        ]
        
        perms = set()
        for base in bases:
            for suffix in S3_SUFFIXES:
                perms.add(f"{base}{suffix}")
        print(f"[S3] Generated {len(perms)} bucket name permutations")

        return list(perms)


    def _check_bucket(self, bucket_name: str) -> dict:
        result = {
            "bucket_name":    bucket_name,
            "url":            None,
            "exists":         False,
            "is_public":      False,
            "allows_listing": False,
            "exposed_files":  [],
            "severity":       None,
        }
        urls_to_try = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}"
        ]

        for url in urls_to_try:
            try:
                resp = self.http.get(url, timeout=S3_TIMEOUT, allow_redirects=True)

                if resp.status_code == 404:
                    continue

                if resp.status_code == 403:
                    result.update({
                        "exists":   True,
                        "url":      url,
                        "severity": "MEDIUM"
                    })
                    break

                if resp.status_code == 200:
                    files   = self._parse_listing(resp.text)
                    listing = files is not None
                    result.update({
                        "exists":         True,
                        "url":            url,
                        "is_public":      True,
                        "allows_listing": listing,
                        "exposed_files":  files or [],
                        "severity":       self._compute_severity(files or [])
                    })
                    break

                if resp.status_code == 301:
                    result.update({
                        "exists":   True,
                        "url":      url,
                        "severity": "MEDIUM"
                    })
                    break

            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout):
                continue

            except Exception:
                continue

        return result


    def _parse_listing(self, xml_text: str) -> list[str] | None:
        try:
            root = ET.fromstring(xml_text)
            if "ListBucketResult" not in root.tag:
                return None
            files = []
            for content in root.findall(f"{S3_NAMESPACE}Contents"):
                key = content.find(f"{S3_NAMESPACE}Key")
                if key is not None:
                    files.append(key.text)
            return files

        except ET.ParseError:
            return None

    def _compute_severity(self, files: list[str]) -> str:
        if not files:
            return "HIGH"
        
        files_lower = [f.lower() for f in files]
        for pattern in SENSITIVE_PATTERNS:
            if any(pattern in f for f in files_lower):
                return "CRITICAL"

        return "HIGH"

    def scan(self) -> list[dict]:
        print(f"[S3] Scanning buckets for: {self.company}")
        permutations = self._generate_permutations()
        findings     = []
        total        = len(permutations)

        for i, name in enumerate(permutations, 1):
            print(f"  Checking [{i}/{total}]: {name}", end="\r")
            result = self._check_bucket(name)
            if result["exists"]:
                findings.append(result)

        print(f"\n[S3] Done — {len(findings)} buckets found")
        return findings