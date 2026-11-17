"""
Security helpers added on the tapfin security/hardening branch.

Covers:
- server-side 2FA enrolment enforcement (token auth for users without TOTP)
- client IP resolution from a trusted number of reverse proxies
- outbound URL validation for URL actions / webhooks (SSRF)
- TOTP verification with a narrow window and replay protection
"""

import ipaddress
import socket
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlsplit

from django.conf import settings
from django.core.cache import cache
from knox.auth import TokenAuthentication
from rest_framework import exceptions

if TYPE_CHECKING:
    from accounts.models import User

# endpoints a user without TOTP may call with the short-lived token issued by
# /v2/checkcreds/, so the dashboard can finish TOTP enrolment
TOTP_ENROLMENT_PATHS = (
    "/accounts/users/setup_totp/",
    "/logout/",
    "/logoutall/",
)


def requires_totp_enrolment(user: "User") -> bool:
    """True for a local dashboard user who has not set up TOTP yet."""
    if not getattr(user, "is_authenticated", False):
        return False
    if user.totp_key:
        return False
    if getattr(settings, "DEMO", False):
        return False
    if getattr(settings, "TRMM_ENFORCE_2FA", True) is False:
        return False
    # agents and installer users authenticate with DRF tokens, never TOTP
    if getattr(user, "agent_id", None) or getattr(user, "is_installer_user", False):
        return False
    # SSO users are authenticated by their identity provider
    return not user.is_sso_user


class EnforcedTOTPKnoxAuthentication(TokenAuthentication):
    """
    Knox token auth that refuses every endpoint except TOTP enrolment for
    users who have no TOTP key. Upstream only enforced this in the browser.
    """

    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None

        user, auth_token = result
        if requires_totp_enrolment(user) and request.path not in TOTP_ENROLMENT_PATHS:
            raise exceptions.AuthenticationFailed(
                "Two-factor authentication must be set up before using the API."
            )

        return user, auth_token


def get_client_ip(meta) -> str:
    """
    Resolve the client IP the same way for logging, auditing and throttling.

    TRMM_NUM_PROXIES is the number of reverse proxies in front of the app that
    append to X-Forwarded-For (the bundled nginx counts as one). Entries left of
    those are client-controlled and are ignored. 0 = trust REMOTE_ADDR only.
    """
    num_proxies = int(getattr(settings, "TRMM_NUM_PROXIES", 1))
    remote_addr = meta.get("REMOTE_ADDR", "") or ""
    xff = meta.get("HTTP_X_FORWARDED_FOR", "") or ""

    if num_proxies > 0 and xff:
        addrs = [a.strip() for a in xff.split(",") if a.strip()]
        if addrs:
            return addrs[-min(num_proxies, len(addrs))]

    return remote_addr.strip()


class OutboundURLError(ValueError):
    pass


def _ip_is_blocked(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None and _ip_is_blocked(ip.ipv4_mapped))  # type: ignore
    )


def validate_outbound_url(url: str) -> None:
    """
    Refuse URL actions / webhooks that target internal networks (SSRF).

    TRMM_URL_ACTION_ALLOW_PRIVATE = True disables the check.
    TRMM_URL_ACTION_ALLOWED_HOSTS = ["n8n.internal", ...] allows named hosts.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise OutboundURLError(f"URL scheme '{parts.scheme}' is not allowed")

    host = parts.hostname
    if not host:
        raise OutboundURLError("URL has no host")

    if getattr(settings, "TRMM_URL_ACTION_ALLOW_PRIVATE", False):
        return

    allowed_hosts = [
        h.lower() for h in getattr(settings, "TRMM_URL_ACTION_ALLOWED_HOSTS", [])
    ]
    if host.lower() in allowed_hosts:
        return

    try:
        infos = socket.getaddrinfo(host, parts.port or None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise OutboundURLError(f"Could not resolve {host}: {e}")

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if _ip_is_blocked(ip):
            raise OutboundURLError(
                f"{host} resolves to a private or internal address, which is not allowed"
            )


def verify_totp(user: "User", token: Optional[str]) -> bool:
    """Verify a TOTP code with a +/-1 step window; each code works only once."""
    import pyotp

    if not user.totp_key or not token:
        return False

    token = str(token).strip()
    totp = pyotp.TOTP(user.totp_key)
    window = int(getattr(settings, "TRMM_TOTP_VALID_WINDOW", 1))
    if not totp.verify(token, valid_window=window):
        return False

    # replay protection: remember the code for longer than its validity
    return cache.add(f"totp_used:{user.pk}:{token}", 1, timeout=30 * (2 * window + 2))
