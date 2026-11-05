from django.core.management.base import BaseCommand, CommandError

from accounts.roles import MissingPermission, ROLE_PERMISSIONS, ensure_roles


class Command(BaseCommand):
    help = "Create the 'analyst' and 'viewer' groups with their permissions (idempotent)."

    def handle(self, *args, **options):
        try:
            groups = ensure_roles()
        except MissingPermission as exc:
            raise CommandError(str(exc)) from exc
        for name in groups:
            self.stdout.write(
                self.style.SUCCESS(f"Group '{name}' ready ({len(ROLE_PERMISSIONS[name])} permissions).")
            )
        self.stdout.write(
            "Assign users to a group in /admin/ (Users > user > Groups). "
            "Superusers can do everything without a group."
        )
