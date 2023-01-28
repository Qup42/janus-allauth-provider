from allauth.socialaccount.providers.oauth2.urls import default_urlpatterns
from django.urls import path

from .app_settings import ALLAUTH_JANUS_LOGOUT
from .provider import JanusProvider


urlpatterns = default_urlpatterns(JanusProvider)

if ALLAUTH_JANUS_LOGOUT == "remote_oidc":
    from allauth_janus.views import oidc_logout
    urlpatterns += [
        path("logout/", oidc_logout, name=f"{JanusProvider.id}_logout")
    ]
