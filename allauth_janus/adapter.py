from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.adapter import DefaultAccountAdapter
from allauth_janus.signals import save_jwt_token


class AllowNewUsersSocialAccountAdapter(DefaultSocialAccountAdapter):

    def save_user(self, request, sociallogin, form=None):
        ret = super().save_user(request, sociallogin, form)

        if "id_token" in request.session:
            save_jwt_token(request.session.pop("id_token"), sociallogin)

        return ret

    def is_open_for_signup(self, request, sociallogin):
        return True

class NoNewUsersAccountAdapter(DefaultAccountAdapter):

    def is_open_for_signup(self, request):
        return False