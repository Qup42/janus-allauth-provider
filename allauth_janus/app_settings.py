from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import warnings

# False to not break existing deployments. Uses old custom endpoints when disabled.
ALLAUTH_JANUS_OIDC = getattr(settings, "ALLAUTH_JANUS_OIDC", False)

ALLAUTH_JANUS_LOGOUT = getattr(settings, "ALLAUTH_JANUS_LOGOUT", "local")
if bool(getattr(settings, "ALLAUTH_JANUS_REMOTE_LOGOUT", False)):
    warnings.warn("ALLAUTH_JANUS_REMOTE_LOGOUT will be deprecated in a future release. Set ALLAUTH_JANUS_LOGOUT to `remote_custom` instead.",
                  PendingDeprecationWarning)
    if ALLAUTH_JANUS_LOGOUT != "local":
        raise ImproperlyConfigured("ALLAUTH_JANUS_LOGOUT and ALLAUTH_JANUS_REMOTE_LOGOUT are not compatible.")
    else:
        ALLAUTH_JANUS_LOGOUT = "remote_custom"

if ALLAUTH_JANUS_OIDC:
    ALLAUTH_JANUS_PROFILE_URL = settings.ALLAUTH_JANUS_URL + '/o/userinfo/'
else:
    ALLAUTH_JANUS_PROFILE_URL = settings.ALLAUTH_JANUS_URL + '/o/profile/'
