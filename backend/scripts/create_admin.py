"""Create the first local ThreatScope XDR administrator without exposing secrets."""

import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import models  # noqa: E402,F401
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.modules.access_control.models import UserAccount  # noqa: E402
from app.modules.access_control.password_service import PasswordPolicyError  # noqa: E402
from app.modules.access_control.role_service import seed_roles_and_permissions  # noqa: E402
from app.modules.access_control.user_service import create_user  # noqa: E402


def _environment_values() -> tuple[str, str, str, str | None] | None:
    names = (
        "THREATSCOPE_BOOTSTRAP_ADMIN_USERNAME",
        "THREATSCOPE_BOOTSTRAP_ADMIN_PASSWORD",
        "THREATSCOPE_BOOTSTRAP_ADMIN_DISPLAY_NAME",
    )
    values = [os.getenv(name) for name in names]
    if not any(values):
        return None
    if not all(values):
        raise ValueError("All three bootstrap administrator variables are required")
    return values[0], values[1], values[2], os.getenv("THREATSCOPE_BOOTSTRAP_ADMIN_EMAIL")


def bootstrap_from_environment() -> bool:
    values = _environment_values()
    if values is None:
        return False
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        if db.query(UserAccount).count():
            return False
        seed_roles_and_permissions(db)
        create_user(
            db,
            username=values[0],
            password=values[1],
            display_name=values[2],
            email=values[3],
            role_keys=["administrator"],
            must_change_password=False,
            is_system_admin=True,
        )
        return True


def interactive_create() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        if db.query(UserAccount).count():
            raise ValueError("Administrator bootstrap refused because user accounts already exist")
        seed_roles_and_permissions(db)
        username = input("Administrator username: ").strip()
        display_name = input("Display name: ").strip()
        email = input("Email (optional): ").strip() or None
        password = getpass.getpass("Password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise ValueError("Password confirmation does not match")
        create_user(
            db,
            username=username,
            display_name=display_name,
            email=email,
            password=password,
            role_keys=["administrator"],
            must_change_password=False,
            is_system_admin=True,
        )


def main() -> int:
    try:
        if _environment_values() is not None:
            created = bootstrap_from_environment()
            print("Initial administrator created successfully." if created else "Bootstrap skipped because user accounts already exist.")
        else:
            interactive_create()
            print("Initial administrator created successfully.")
        return 0
    except (ValueError, PasswordPolicyError) as exc:
        print(f"Administrator creation failed: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print("Administrator creation failed safely. Review database and environment configuration.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

