from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path
from django.views.generic import RedirectView

urlpatterns = [
    path("", RedirectView.as_view(pattern_name="alerts:queue", permanent=False)),
    path("admin/", admin.site.urls),
    path("login/", auth_views.LoginView.as_view(redirect_authenticated_user=True), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("alerts/", include("alerts.urls")),
    path("incidents/", include("incidents.urls")),
    path("reports/", include("reports.urls")),
    path("settings/", include("accounts.urls")),
]
