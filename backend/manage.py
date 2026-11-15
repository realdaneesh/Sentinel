"""Local security administration commands; no HTTP routes are registered here."""

import argparse
import getpass
import sys

from sqlalchemy import func, select

from .database import SessionLocal, init_db
from .models.user import User
from .services.audit_service import record_audit_log
from .services.auth_service import create_user
from .services.producer_service import provision_producer, revoke_producer, rotate_producer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local Sentinel security administration")
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap = commands.add_parser("bootstrap-admin", help="Create an admin only if none is active")
    bootstrap.add_argument("--username", required=True)
    provision = commands.add_parser("provision-producer", help="Create a source-bound producer key")
    provision.add_argument("--name", required=True)
    provision.add_argument("--source", required=True)
    revoke = commands.add_parser("revoke-producer", help="Disable a producer key")
    revoke.add_argument("--id", required=True)
    rotate = commands.add_parser("rotate-producer", help="Replace a producer key")
    rotate.add_argument("--id", required=True)
    args = parser.parse_args(argv)

    init_db()
    with SessionLocal() as db:
        if args.command == "bootstrap-admin":
            active_admins = db.scalar(select(func.count()).select_from(User).where(
                User.role == "admin", User.account_status == "active"
            ))
            if active_admins:
                parser.error("An active administrator already exists")
            password = getpass.getpass("New admin password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm or len(password) < 8 or len(password.encode("utf-8")) > 72:
                parser.error("Passwords must match and be 8 to 72 UTF-8 bytes")
            user = create_user(db, username=args.username, password=password, role="admin")
            record_audit_log(db, actor="local/bootstrap", action="BOOTSTRAP_ADMIN",
                             resource_type="user", resource_id=user.id,
                             details={"username": user.username})
            print(f"Created administrator {user.username} ({user.id})")
        elif args.command == "provision-producer":
            producer, key = provision_producer(db, name=args.name, source=args.source)
            print(f"Producer ID: {producer.id}\nSource: {producer.source}\nKey (shown once): {key}")
        elif args.command == "revoke-producer":
            if revoke_producer(db, args.id) is None:
                parser.error("Producer not found")
            print("Producer revoked")
        elif args.command == "rotate-producer":
            rotated = rotate_producer(db, args.id)
            if rotated is None:
                parser.error("Active producer not found")
            print(f"Replacement key (shown once): {rotated[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
