from allauth.socialaccount import app_settings as allauth_app_settings
from allauth_janus.app_settings import ALLAUTH_JANUS_PROFILE_URL

import requests

from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)
from django.conf import settings

from .models import JWTToken
from .provider import JanusProvider


class JanusOAuth2Adapter(OAuth2Adapter):
    provider_id = JanusProvider.id
    access_token_url = settings.ALLAUTH_JANUS_URL + '/o/token/'
    authorize_url = settings.ALLAUTH_JANUS_URL + '/o/authorize/'
    profile_url = ALLAUTH_JANUS_PROFILE_URL
    supports_state = True
    redirect_uri_protocol = settings.ALLAUTH_JANUS_REDIRECT_PROTOCOL

    def complete_login(self, request, app, token, **kwargs):
        response = requests.get(
            self.profile_url,
            headers={"Authorization": f"Bearer {token}"})
        extra_data = response.json()

        if allauth_app_settings.STORE_TOKENS and "id_token" in kwargs.get("response", {}):
            jwt_token = kwargs["response"]["id_token"]
            # allauth copies the SocialToken by hand and the OneToOne Reference
            # of the JWTToken gets lost in the process. I found no ways to modify
            # this behaviour. So we have to temporarily store it in the session.
            request.session["id_token"] = jwt_token

        return self.get_provider().sociallogin_from_response(
            request,
            extra_data)


oauth2_login = OAuth2LoginView.adapter_view(JanusOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(JanusOAuth2Adapter)
