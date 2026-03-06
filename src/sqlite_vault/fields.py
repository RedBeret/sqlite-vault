"""Field descriptors for sqlite-vault schema definitions.

EncryptedField and PlainField mark columns in a VaultDB schema. Both handle
serialization to/from SQLite storage, with EncryptedField transparently
encrypting/decrypting values through a CryptoBackend.
"""

from typing import Any, Literal


class EncryptedField:
    """A field whose values are encrypted at rest in SQLite.

    Stored as TEXT (Fernet ciphertext). Automatically encrypted on write
    and decrypted on read when accessed through VaultDB.

    Example::

        schema = {
            "users": {
                "email": EncryptedField(),
                "name": EncryptedField(),
            }
        }
    """

    @property
    def sql_type(self) -> str:
        """SQLite column type — always TEXT for ciphertext."""
        return "TEXT"

    def to_db(self, value: Any, crypto: Any) -> str | None:
        """Encrypt value for storage. Returns None if value is None."""
        if value is None:
            return None
        return crypto.encrypt(str(value))

    def from_db(self, value: Any, crypto: Any) -> str | None:
        """Decrypt value from storage. Returns None if value is None."""
        if value is None:
            return None
        return crypto.decrypt(str(value))


class PlainField:
    """A field whose values are stored as-is (unencrypted) in SQLite.

    Supports common SQLite types. Use plain fields for values you need
    to filter, sort, or aggregate directly in SQL queries.

    Args:
        dtype: SQLite column type. One of TEXT, INTEGER, REAL, BLOB.
               Defaults to TEXT.

    Example::

        schema = {
            "users": {
                "role": PlainField(),
                "score": PlainField(dtype="REAL"),
                "created_at": PlainField(dtype="TEXT"),
            }
        }
    """

    _VALID_TYPES: frozenset[str] = frozenset({"TEXT", "INTEGER", "REAL", "BLOB"})

    def __init__(
        self, dtype: Literal["TEXT", "INTEGER", "REAL", "BLOB"] = "TEXT"
    ) -> None:
        if dtype.upper() not in self._VALID_TYPES:
            raise ValueError(
                f"Invalid dtype '{dtype}'. Must be one of: {', '.join(sorted(self._VALID_TYPES))}"
            )
        self._dtype = dtype.upper()

    @property
    def sql_type(self) -> str:
        """SQLite column type."""
        return self._dtype

    def to_db(self, value: Any, crypto: Any) -> Any:
        """Pass value through unchanged for storage."""
        return value

    def from_db(self, value: Any, crypto: Any) -> Any:
        """Pass value through unchanged from storage."""
        return value
