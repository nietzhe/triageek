"""Server-side permission checks for views."""

from functools import wraps

from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied


def needs_perm(perm: str):
    """Require a logged-in user holding ``perm``.

    Anonymous users are redirected to the login page; logged-in users without the
    permission (for example viewers on a write endpoint) get a 403.
    """

    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect_to_login(request.get_full_path())
            if not request.user.has_perm(perm):
                raise PermissionDenied
            return view(request, *args, **kwargs)

        return wrapper

    return decorator
