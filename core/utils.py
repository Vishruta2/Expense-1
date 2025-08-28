from pathlib import Path
from django.conf import settings

USERS_FILE = Path(settings.BASE_DIR) / "users.txt"

def load_users():
    """
    Returns dict:
      {
        "username": {"password": "...", "role": "EMPLOYEE"|"ACCOUNTANT"|"DEPARTMENT_HEAD"|"FINANCE_HEAD"}
      }
    Each non-empty, non-# line in users.txt can be:
      username, password
      username, password, role
    If role missing -> EMPLOYEE.
    """
    users = {}
    if USERS_FILE.exists():
        for raw in USERS_FILE.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                username = parts[0]
                password = parts[1]
                role = (parts[2] if len(parts) >= 3 else "EMPLOYEE").upper().replace(" ", "_")
                users[username] = {"password": password, "role": role}
    return users