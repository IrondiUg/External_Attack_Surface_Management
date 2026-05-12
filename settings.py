import os
from dotenv import load_dotenv
load_dotenv()

TARGET_DOMAIN = os.getenv("TARGET_DOMAIN", "example.com")
COMPANY_NAME  = os.getenv("COMPANY_NAME", "example")

# Timeouts
DNS_TIMEOUT  = 5
HTTP_TIMEOUT = 10
S3_TIMEOUT   = 8

# S3 permutation suffixes
S3_SUFFIXES = [
    "", "-dev", "-staging", "-prod", "-production",
    "-backup", "-backups", "-data", "-assets", "-uploads",
    "-static", "-media", "-logs", "-public", "-private",
    "-internal", "-test", "-testing", "-uat", "-qa",
    "-archive", "-old", "-new", "-web", "-api",
    "-files", "-storage", "-bucket", "-s3",
    "-database", "-db", "-config", "-secrets",
]

# Nuclei
NUCLEI_SEVERITIES = "medium,high,critical"
NUCLEI_RATE_LIMIT = "50"
NUCLEI_TIMEOUT    = "10"
