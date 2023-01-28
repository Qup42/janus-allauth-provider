from urllib.parse import parse_qsl, urlsplit, urlencode, urlunsplit

from allauth.socialaccount import app_settings as allauth_app_settings
from allauth.socialaccount.providers.openid_connect.views import OpenIDConnectAdapter
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from django.urls import resolve
from django.utils.decorators import method_decorator

from allauth_janus.app_settings import ALLAUTH_JANUS_PROFILE_URL, ALLAUTH_JANUS_LOGOUT

import requests

from allauth.socialaccount.providers.oauth2.views import (
    OAuth2CallbackView,
    OAuth2LoginView,
    OAuth2View,
)
from django.conf import settings

from .models import JWTToken
from .provider import JanusProvider


class JanusOAuth2Adapter(OpenIDConnectAdapter):
    provider_id = JanusProvider.id
    access_token_url = settings.ALLAUTH_JANUS_URL + '/o/token/'
    authorize_url = settings.ALLAUTH_JANUS_URL + '/o/authorize/'
    profile_url = ALLAUTH_JANUS_PROFILE_URL
    supports_state = True
    redirect_uri_protocol = settings.ALLAUTH_JANUS_REDIRECT_PROTOCOL

    @property
    def end_session_url(self):
        return self.openid_config.get("end_session_endpoint", None)

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


class LogoutView(OAuth2View):

    def build_logout_url(self, app, id_token, request):
        url = urlsplit(self.adapter.end_session_url)
        oidc_rp_initiated_logout_params = [("id_token_hint", id_token.jwt_token),
                                           ("client_id", app.client_id),
                                           ("post_logout_redirect_uri", request.build_absolute_uri(getattr(settings, "LOGOUT_REDIRECT_URL", "/")))]
        query = urlencode(parse_qsl(url.query) + oidc_rp_initiated_logout_params)
        return urlunsplit((url.scheme, url.netloc, url.path, query, url.fragment))

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        app = self.adapter.get_provider().get_app(self.request)
        id_tokens_user = JWTToken.objects.filter(social_token__app=app, social_token__account__user=request.user)
        if id_tokens_user.count() == 0 or not self.adapter.end_session_url:
            # Just logout at the RP.
            logout(request)
            return HttpResponseRedirect(redirect_to=resolve(settings.LOGOUT_REDIRECT_URL))
        elif ALLAUTH_JANUS_LOGOUT == "remote_oidc" and id_tokens_user.count() >= 1:
            # Logout at RP and OP using OIDC RP-Initiated Logout.
            id_token = id_tokens_user.first()
            logout(request)
            return HttpResponseRedirect(redirect_to=self.build_logout_url(app, id_token, request))


oauth2_login = OAuth2LoginView.adapter_view(JanusOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(JanusOAuth2Adapter)
oidc_logout = LogoutView.adapter_view(JanusOAuth2Adapter)
