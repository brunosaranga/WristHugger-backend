from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path

from .views import RegisterClientView, AuthorizeView, TokenView
from .resource_views import ProtectedResourceView

app_name = "core"

urlpatterns = [
    path("login/", LoginView.as_view(template_name="core/login.html"), name="login"),
    path("logout/", LogoutView.as_view(next_page="core:login"), name="logout"),


    path("clients/register/", RegisterClientView.as_view(), name="register_client"),

    path("authorize/", AuthorizeView.as_view(), name="authorize"),

    path("token/", TokenView.as_view(), name="token"),

    path("api/me/", ProtectedResourceView.as_view(), name="protected_resource"),
]