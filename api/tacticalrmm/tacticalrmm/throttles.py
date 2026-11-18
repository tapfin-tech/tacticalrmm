from rest_framework.throttling import AnonRateThrottle


class TrustedProxyAnonThrottle(AnonRateThrottle):
    """Throttle by the client IP resolved from the trusted proxy count."""

    def get_ident(self, request):
        from tacticalrmm.security import get_client_ip

        return get_client_ip(request.META)


class CheckCredsMinThrottle(TrustedProxyAnonThrottle):
    scope = "check_creds_min"


class CheckCredsDayThrottle(TrustedProxyAnonThrottle):
    scope = "check_creds_day"


class LoginMinThrottle(TrustedProxyAnonThrottle):
    scope = "login_min"


class LoginDayThrottle(TrustedProxyAnonThrottle):
    scope = "login_day"
