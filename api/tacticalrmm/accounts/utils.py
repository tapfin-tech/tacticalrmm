from typing import TYPE_CHECKING

from django.conf import settings

if TYPE_CHECKING:
    from django.http import HttpRequest

    from accounts.models import User


def is_root_user(*, request: "HttpRequest", user: "User") -> bool:
    root = (
        hasattr(settings, "ROOT_USER")
        and request.user != user
        and user.username == settings.ROOT_USER
    )
    demo = (
        getattr(settings, "DEMO", False) and request.user.username == settings.ROOT_USER
    )
    return root or demo


def is_superuser(user: "User") -> bool:
    return user.role and getattr(user.role, "is_superuser")


def is_effective_superuser(user: "User") -> bool:
    """Django superuser flag or a superuser role."""
    return bool(
        getattr(user, "is_superuser", False)
        or (user.role and getattr(user.role, "is_superuser", False))
    )


SUPERUSER_ONLY_MSG = "Only a superuser can change a superuser account or role"


def privilege_change_error(
    *, request: "HttpRequest", target: "User | None" = None, role=None
) -> "str | None":
    """
    Stop users with account or role management rights from escalating to
    superuser: only a superuser may modify a superuser account, or hand out
    or edit a superuser role. Returns an error message, or None when allowed.
    """
    if is_effective_superuser(request.user):  # type: ignore
        return None
    if target is not None and is_effective_superuser(target):
        return SUPERUSER_ONLY_MSG
    if role is not None and getattr(role, "is_superuser", False):
        return SUPERUSER_ONLY_MSG
    return None
