from allauth.socialaccount.models import SocialToken
from django.db import models


class JWTToken(models.Model):
    jwt_token = models.TextField(verbose_name="JWT Token")
    social_token = models.OneToOneField(SocialToken, on_delete=models.CASCADE)
