import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cspm.db")
# If set, every /api request must send a matching X-API-Key header.
API_KEY = os.getenv("CSPM_API_KEY", "")
MAX_IMPORT_FINDINGS = int(os.getenv("CSPM_MAX_IMPORT_FINDINGS", "50000"))
