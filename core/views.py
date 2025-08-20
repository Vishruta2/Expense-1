import hmac
from pathlib import Path
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages
from django.views.decorators.http import require_http_methods

USERS_FILE = Path(settings.BASE_DIR) / "users.txt"  # keep users.txt next to manage.py

def _load_users():
    """Return dict {username: password} from users.txt (ignores blank/# lines)."""
    users = {}
    if USERS_FILE.exists():
        for line in USERS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",", 1)]
            if len(parts) == 2:
                users[parts[0]] = parts[1]
    return users

@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        password = (request.POST.get("password") or "").strip()

        expected = _load_users().get(username)
        if expected and hmac.compare_digest(password, expected):
            messages.success(request, "Login successful!")
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid username or password!")
            return redirect("login")

    return render(request, "login.html")

def dashboard(request):
    return render(request, "dashboard.html")
