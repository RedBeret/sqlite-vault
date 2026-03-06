"""sqlite-vault: Transparent field-level encryption for SQLite.

Quick start::

    from sqlite_vault import VaultDB, EncryptedField, PlainField

    schema = {
        "users": {
            "name": EncryptedField(),
            "email": EncryptedField(),
            "role": PlainField(),
        }
    }

    with VaultDB("myapp.db", password="secret") as db:
        db.create_tables(schema)
        db.insert("users", name="Alice", email="alice@example.com", role="admin")
        users = db.query("users", where={"role": "admin"})
        print(users[0]["name"])  # "Alice"
"""

from .crypto import KeychainCrypto, PasswordCrypto
from .fields import EncryptedField, PlainField
from .vault import VaultDB

__all__ = ["VaultDB", "EncryptedField", "PlainField", "KeychainCrypto", "PasswordCrypto"]
__version__ = "0.1.0"
