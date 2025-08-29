# core/urls.py
from django.urls import path
from .views import login_view, dashboard_view, accountant_dashboard_view, logout_view

app_name = "core"  # <-- this declares the namespace "core"

urlpatterns = [
    path("", login_view, name="login"),
    path("dashboard/", dashboard_view, name="dashboard"),
    path("accountant/", accountant_dashboard_view, name="accountant_dashboard"),
    path("logout/", logout_view, name="logout"),
]
