from urllib.parse import urlsplit, urlencode, parse_qsl, urlunsplit

from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.adapter import DefaultAccountAdapter
from django.conf import settings

from allauth_janus import ALLAUTH_JANUS_LOGOUT
from allauth_janus.models import JWTToken
from allauth_janus.views import JanusOAuth2Adapter
from allauth_janus.signals import save_jwt_token


class AllowNewUsersSocialAccountAdapter(DefaultSocialAccountAdapter):

    def save_user(self, request, sociallogin, form=None):
        ret = super().save_user(request, sociallogin, form)

        if "id_token" in request.session:
            save_jwt_token(request.session.pop("id_token"), sociallogin)

        return ret

    def is_open_for_signup(self, request, sociallogin):
        return True


def build_logout_url(adapter, app, id_token, request):
    url = urlsplit(adapter.end_session_url)
    oidc_rp_initiated_logout_params = [("id_token_hint", id_token.jwt_token),
                                       ("client_id", app.client_id),
                                       ("post_logout_redirect_uri", request.build_absolute_uri(getattr(settings, "LOGOUT_REDIRECT_URL", "/")))]
    query = urlencode(parse_qsl(url.query) + oidc_rp_initiated_logout_params)
    return urlunsplit((url.scheme, url.netloc, url.path, query, url.fragment))


class NoNewUsersAccountAdapter(DefaultAccountAdapter):

    def get_logout_redirect_url(self, request):
        adapter = JanusOAuth2Adapter(request)
        app = adapter.get_provider().get_app(request)
        id_tokens_user = JWTToken.objects.filter(social_token__app=app, social_token__account__user=request.user)

        # TODO: should ideally be mutually exclusive or have the default case as local logout
        # TODO: integrate
        if id_tokens_user.count() == 0 or not adapter.end_session_url:
            # Just logout at the RP.
            return settings.LOGOUT_REDIRECT_URL
        elif ALLAUTH_JANUS_LOGOUT == "remote_oidc" and id_tokens_user.count() >= 1:
            # Logout at RP and OP using OIDC RP-Initiated Logout.
            id_token = id_tokens_user.first()
            return build_logout_url(adapter, app, id_token, request)

    def is_open_for_signup(self, request):
        return False
