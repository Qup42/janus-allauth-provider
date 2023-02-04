from allauth.socialaccount.admin import SocialTokenAdmin, SocialToken
from .models import JWTToken
from django.contrib import admin


class JWTTokenAdmin(admin.StackedInline):
    model = JWTToken


class ExtendedSocialTokenAdmin(SocialTokenAdmin):
    inlines = SocialTokenAdmin.inlines + [JWTTokenAdmin]


admin.site.unregister(SocialToken)
admin.site.register(SocialToken, ExtendedSocialTokenAdmin)
