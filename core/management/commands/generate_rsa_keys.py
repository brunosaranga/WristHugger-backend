from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Generate an RSA keypair for signing access token. Run once per environment."

    def handle(self, *args, **kwargs):
        private_path = Path(settings.OAUTH_PRIVATE_KEY_PATH)
        public_path = Path(settings.OAUTH_PUBLIC_KEY_PATH)

        if private_path.exists() or public_path.exists():
            self.stdout.write(self.style.WARNING("Key files already exist - remove them first if you want to rotate."))

        private_path.parent.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        private_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        public_path.write_bytes(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        self.stdout.write(self.style.SUCCESS(f"Wrote {private_path} and {public_path}"))