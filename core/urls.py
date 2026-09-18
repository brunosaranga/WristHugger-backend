from django.urls import path

from .views import RegisterClientView, AuthorizeView, TokenView
from .resource_views import ProtectedResourceView

app_name = "core"

urlpatterns = [
    path("clients/register/", RegisterClientView.as_view(), name="register_client"),

    path("authorize/", AuthorizeView.as_view(), name="authorize"),

    path("token/", TokenView.as_view(), name="token"),

    path("api/me/", ProtectedResourceView.as_view(), name="protected_resource"),
]