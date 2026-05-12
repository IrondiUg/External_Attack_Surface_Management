import subprocess
import json
import os
import tempfile
from settings import NUCLEI_SEVERITIES, NUCLEI_RATE_LIMIT, NUCLEI_TIMEOUT

class NucleiScanner:
    def _write_targets(self, targets: list[str]) -> str:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt",
            delete=False, prefix="nuclei_targets_"
        )
        for t in targets:
            tmp.write(f"{t}\n")
        tmp.close()
        return tmp.name


    def _run_nuclei(self, targets_file: str) -> list[dict]:
        output_file = targets_file.replace(".txt", "_out.json")

        cmd = [
            "nuclei",
            "-l",           targets_file,
            "-severity",    NUCLEI_SEVERITIES,
            "-json-export", output_file,
            "-silent",
            "-no-interactsh",
            "-timeout",     NUCLEI_TIMEOUT,
            "-retries",     "1",
            "-rate-limit",  NUCLEI_RATE_LIMIT,
        ]

        try:
            subprocess.run(cmd, timeout=3600, check=False)

        except FileNotFoundError:
            print("[Nuclei] ERROR: nuclei not installed.")
            print("  Run: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return []

        except subprocess.TimeoutExpired:
            print("[Nuclei] WARNING: Scan timed out.")
            return []

        findings = []
        if os.path.exists(output_file):
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))

                        except json.JSONDecodeError:
                            continue
            os.remove(output_file)

        os.remove(targets_file)
        return findings

    def _print_finding(self, raw: dict):
        info     = raw.get("info", {})
        severity = info.get("severity", "unknown").upper()
        name     = info.get("name", "unknown")
        host     = raw.get("host", "")
        matched  = raw.get("matched-at", "")
        desc     = info.get("description", "")[:120]
        tags     = ", ".join(info.get("tags", []))
       
        print(f"""
  [FINDING]
  Name:        {name}
  Severity:    {severity}
  Host:        {host}
  Matched URL: {matched}
  Description: {desc}
  Tags:        {tags}
  {'-'*50}""")

    def scan(self, targets: list[str], label: str = ""):
        if not targets:
            print(f"[Nuclei] No targets for {label}, skipping.")
            return

        print(f"\n[Nuclei] Scanning {label} ({len(targets)} targets)...")
        targets_file = self._write_targets(targets)
        raw_findings = self._run_nuclei(targets_file)

        if not raw_findings:
            print(f"[Nuclei] No findings for {label}")
            return

        print(f"[Nuclei] {len(raw_findings)} finding(s) for {label}:")
        for finding in raw_findings:
            self._print_finding(finding)