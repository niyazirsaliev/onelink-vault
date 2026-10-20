import os

VW_URL = os.environ.get("VW_URL", "https://vault.bitwarden.com")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
AUDIT_DB_PATH = os.environ.get("AUDIT_DB_PATH", "/var/lib/vault-gateway/audit.db")
CALLERS_FILE_PATH = os.environ.get("CALLERS_FILE_PATH", "/var/lib/vault-gateway/callers.json")
BW_HOME_BASE = os.environ.get("BW_HOME_BASE", "/var/lib/vault-gateway/bw-homes")
