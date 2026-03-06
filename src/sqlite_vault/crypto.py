"""Encryption backends for sqlite-vault.

Two backends are provided:
- KeychainCrypto: stores the Fernet key in macOS Keychain (macOS only)
- PasswordCrypto: derives a Fernet key from a password via PBKDF2 (cross-platform)

Both implement the CryptoBackend protocol.
"""

import hashlib
import logging
import subprocess
from typing import Protocol

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)


class CryptoBackend(Protocol):
    """Protocol for encryption backends."""

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext string and return ciphertext."""
        ...

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a ciphertext string and return plaintext."""
        ...


class KeychainCrypto:
    """Fernet encryption backed by macOS Keychain.

    On first use, generates a random Fernet key and stores it in the
    macOS Keychain under the given service name. Subsequent uses retrieve
    the key from Keychain automatically.

    Args:
        service_name: Keychain service name used to store the encryption key.
    """

    def __init__(self, service_name: str) -> None:
        self._service_name = service_name
        self._fernet: Fernet | None = None

    def _keychain_get(self) -> str | None:
        """Retrieve the key from macOS Keychain."""
        result = subprocess.run(
            ["security", "find-generic-password", "-s", self._service_name, "-w"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None

    def _keychain_set(self, key: str) -> None:
        """Store the key in macOS Keychain."""
        subprocess.run(
            [
                "security",
                "add-generic-password",
                "-s",
                self._service_name,
                "-a",
                self._service_name,
                "-w",
                key,
                "-U",
            ],
            capture_output=True,
            check=True,
        )

    def _get_fernet(self) -> Fernet:
        if self._fernet is not None:
            return self._fernet

        key = self._keychain_get()
        if not key:
            logger.info(
                "No key found in Keychain for service '%s'. Generating new key.",
                self._service_name,
            )
            key = Fernet.generate_key().decode()
            self._keychain_set(key)

        self._fernet = Fernet(key.encode())
        return self._fernet

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext string, return Fernet ciphertext."""
        return self._get_fernet().encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt Fernet ciphertext, return plaintext string."""
        return self._get_fernet().decrypt(ciphertext.encode()).decode()


class PasswordCrypto:
    """Fernet encryption backed by a password (cross-platform).

    Derives a Fernet-compatible key from the given password using PBKDF2-HMAC-SHA256.
    The salt is deterministic (derived from the password itself) so the same password
    always produces the same key — suitable for persistent storage.

    Args:
        password: The passphrase used to derive the encryption key.
        salt: Optional explicit salt bytes. Defaults to a deterministic salt derived
              from the password. For stronger security, provide a random salt and store it.
    """

    _ITERATIONS = 480_000  # OWASP recommended minimum for PBKDF2-HMAC-SHA256

    def __init__(self, password: str, salt: bytes | None = None) -> None:
        if not password:
            raise ValueError("Password must not be empty")
        self._fernet = self._derive_fernet(password, salt)

    def _derive_fernet(self, password: str, salt: bytes | None) -> Fernet:
        if salt is None:
            # Deterministic salt from password hash — consistent across runs
            salt = hashlib.sha256(password.encode()).digest()[:16]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self._ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext string, return Fernet ciphertext."""
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt Fernet ciphertext, return plaintext string."""
        return self._fernet.decrypt(ciphertext.encode()).decode()
