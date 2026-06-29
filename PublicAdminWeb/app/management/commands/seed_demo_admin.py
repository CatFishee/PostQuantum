from datetime import datetime

from argon2 import PasswordHasher
from django.core.management.base import BaseCommand

from app.db_connection import get_db


class Command(BaseCommand):
    help = "Seed the Mongo-backed demo admin account used by the RA approval flow."

    def add_arguments(self, parser):
        parser.add_argument("--username", default="adminThuydepgai")
        parser.add_argument("--password", default="adminThuydepgai")
        parser.add_argument("--full-name", default="RA Demo Admin")

    def handle(self, *args, **options):
        db = get_db()
        if db is None:
            raise RuntimeError("Database is not connected")

        username = options["username"]
        password = options["password"]
        full_name = options["full_name"]
        ph = PasswordHasher()
        now = datetime.utcnow()

        update_doc = {
            "username": username,
            "role": "admin",
            "password_hash": ph.hash(password),
            "full_name": full_name,
            "pqc_status": "active",
            "updated_at": now,
        }
        db.users.update_one(
            {"username": username},
            {
                "$set": update_doc,
                "$setOnInsert": {"created_at": now},
            },
            upsert=True,
        )
        self.stdout.write(self.style.SUCCESS(f"Seeded admin account: {username}"))
