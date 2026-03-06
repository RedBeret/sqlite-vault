"""VaultDB — the main sqlite-vault API.

VaultDB wraps an SQLite database and provides CRUD operations with transparent
field-level encryption. Define your schema once with EncryptedField/PlainField
descriptors, and VaultDB handles all encrypt/decrypt automatically.
"""

import logging
import sqlite3
from pathlib import Path
from typing import Any

from .crypto import CryptoBackend, KeychainCrypto, PasswordCrypto
from .fields import EncryptedField, PlainField
from .schema import create_table_sql, get_encrypted_columns

logger = logging.getLogger(__name__)


class VaultDB:
    """SQLite database with transparent field-level encryption.

    Open as a context manager. Define your schema with EncryptedField and
    PlainField descriptors. All encrypt/decrypt is handled automatically
    on insert/query/update.

    Args:
        db_path: Path to the SQLite database file.
        keychain_service: macOS Keychain service name for key storage.
                          Use this for persistent single-machine deployments.
        password: Password for key derivation (cross-platform). Use this for
                  portable databases or testing.
        crypto: Provide your own CryptoBackend instance. Overrides
                keychain_service and password if given.

    Exactly one of keychain_service, password, or crypto must be provided.

    Example::

        schema = {
            "contacts": {
                "name": EncryptedField(),
                "email": EncryptedField(),
                "category": PlainField(),
            }
        }

        with VaultDB("contacts.db", password="secret") as db:
            db.create_tables(schema)
            db.insert("contacts", name="Alice", email="alice@example.com", category="work")
            results = db.query("contacts", where={"category": "work"})
            print(results[0]["name"])  # "Alice"
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        keychain_service: str | None = None,
        password: str | None = None,
        crypto: CryptoBackend | None = None,
    ) -> None:
        self._db_path = Path(db_path)

        provided = sum([keychain_service is not None, password is not None, crypto is not None])
        if provided == 0:
            raise ValueError(
                "Provide exactly one of: keychain_service, password, or crypto"
            )
        if provided > 1:
            raise ValueError(
                "Provide exactly one of: keychain_service, password, or crypto — not multiple"
            )

        if crypto is not None:
            self._crypto = crypto
        elif password is not None:
            self._crypto = PasswordCrypto(password)
        else:
            self._crypto = KeychainCrypto(keychain_service)  # type: ignore[arg-type]

        self._conn: sqlite3.Connection | None = None
        # Maps table name → frozenset of encrypted column names
        self._encrypted_cols: dict[str, frozenset[str]] = {}
        # Maps table name → field schema dict
        self._schemas: dict[str, dict] = {}

    # ── Context manager ──────────────────────────────────────────────────────

    def __enter__(self) -> "VaultDB":
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        return self

    def __exit__(self, *args: Any) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError(
                "VaultDB must be used as a context manager: `with VaultDB(...) as db:`"
            )
        return self._conn

    # ── Schema ───────────────────────────────────────────────────────────────

    def create_tables(self, schema: dict[str, dict]) -> None:
        """Create tables from a schema dict.

        Args:
            schema: Mapping of table name → {column_name: Field, ...}.
                    Tables that already exist are skipped (IF NOT EXISTS).

        Example::

            db.create_tables({
                "notes": {
                    "title": EncryptedField(),
                    "body": EncryptedField(),
                    "created_at": PlainField(),
                }
            })
        """
        conn = self._require_conn()
        for table_name, fields in schema.items():
            sql = create_table_sql(table_name, fields)
            logger.debug("create_tables: %s", sql)
            conn.execute(sql)
            self._schemas[table_name] = fields
            self._encrypted_cols[table_name] = get_encrypted_columns(fields)
        conn.commit()

    def _register_table(self, table: str) -> None:
        """Lazy-load schema info from DB if not already registered."""
        if table in self._schemas:
            return
        # Table was created in a prior session — we don't know the schema,
        # so default to treating all columns as plain.
        logger.warning(
            "Table '%s' was not registered via create_tables() this session. "
            "All columns will be treated as plaintext. Call create_tables() to enable encryption.",
            table,
        )
        self._schemas[table] = {}
        self._encrypted_cols[table] = frozenset()

    def _encrypt_row(self, table: str, kwargs: dict) -> dict:
        """Encrypt values for encrypted columns before insert/update."""
        enc_cols = self._encrypted_cols.get(table, frozenset())
        fields = self._schemas.get(table, {})
        result = {}
        for col, value in kwargs.items():
            if col in fields:
                result[col] = fields[col].to_db(value, self._crypto)
            elif col in enc_cols:
                result[col] = self._crypto.encrypt(str(value)) if value is not None else None
            else:
                result[col] = value
        return result

    def _decrypt_row(self, table: str, row: sqlite3.Row) -> dict:
        """Decrypt encrypted columns from a DB row."""
        enc_cols = self._encrypted_cols.get(table, frozenset())
        fields = self._schemas.get(table, {})
        result = {}
        for key in row.keys():
            raw = row[key]
            if key in fields:
                result[key] = fields[key].from_db(raw, self._crypto)
            elif key in enc_cols and raw is not None:
                result[key] = self._crypto.decrypt(str(raw))
            else:
                result[key] = raw
        return result

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def insert(self, table: str, **kwargs: Any) -> int:
        """Insert a row, encrypting encrypted fields automatically.

        Args:
            table: Table name.
            **kwargs: Column values. Encrypted columns are auto-encrypted.

        Returns:
            The rowid (integer primary key) of the new row.
        """
        conn = self._require_conn()
        self._register_table(table)
        row = self._encrypt_row(table, kwargs)

        cols = ", ".join(row.keys())
        placeholders = ", ".join("?" * len(row))
        sql = f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"
        logger.debug("insert: %s — %d columns", table, len(row))

        cur = conn.execute(sql, tuple(row.values()))
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def query(
        self,
        table: str,
        where: dict[str, Any] | None = None,
        order_by: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Query rows, decrypting encrypted fields automatically.

        Args:
            table: Table name.
            where: Optional equality filters. Only plain fields are supported
                   in WHERE clauses (can't filter on ciphertext).
            order_by: Optional ORDER BY clause (e.g., "created_at DESC").
            limit: Maximum number of rows to return.

        Returns:
            List of dicts with decrypted values.
        """
        conn = self._require_conn()
        self._register_table(table)

        sql = f"SELECT * FROM {table}"
        params: list[Any] = []

        if where:
            enc_cols = self._encrypted_cols.get(table, frozenset())
            for col in where:
                if col in enc_cols:
                    raise ValueError(
                        f"Cannot filter on encrypted column '{col}'. "
                        "Use a plain field for values you need to query."
                    )
            conditions = " AND ".join(f"{col} = ?" for col in where)
            sql += f" WHERE {conditions}"
            params.extend(where.values())

        if order_by:
            sql += f" ORDER BY {order_by}"
        if limit is not None:
            sql += f" LIMIT {limit}"

        logger.debug("query: %s WHERE %s", table, where)
        rows = conn.execute(sql, params).fetchall()
        return [self._decrypt_row(table, row) for row in rows]

    def update(self, table: str, where: dict[str, Any], **kwargs: Any) -> int:
        """Update rows matching where clause, encrypting fields automatically.

        Args:
            table: Table name.
            where: Equality conditions to match rows (plain fields only).
            **kwargs: Column values to update. Encrypted columns are auto-encrypted.

        Returns:
            Number of rows updated.
        """
        conn = self._require_conn()
        self._register_table(table)

        enc_cols = self._encrypted_cols.get(table, frozenset())
        for col in where:
            if col in enc_cols:
                raise ValueError(
                    f"Cannot filter on encrypted column '{col}' in WHERE clause."
                )

        updates = self._encrypt_row(table, kwargs)
        set_clause = ", ".join(f"{col} = ?" for col in updates)
        where_clause = " AND ".join(f"{col} = ?" for col in where)
        sql = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
        params = list(updates.values()) + list(where.values())

        logger.debug("update: %s WHERE %s, SET %s", table, where, list(updates.keys()))
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.rowcount

    def delete(self, table: str, where: dict[str, Any]) -> int:
        """Delete rows matching where clause.

        Args:
            table: Table name.
            where: Equality conditions to match rows (plain fields only).

        Returns:
            Number of rows deleted.
        """
        conn = self._require_conn()
        self._register_table(table)

        enc_cols = self._encrypted_cols.get(table, frozenset())
        for col in where:
            if col in enc_cols:
                raise ValueError(
                    f"Cannot filter on encrypted column '{col}' in WHERE clause."
                )

        where_clause = " AND ".join(f"{col} = ?" for col in where)
        sql = f"DELETE FROM {table} WHERE {where_clause}"

        logger.debug("delete: %s WHERE %s", table, where)
        cur = conn.execute(sql, list(where.values()))
        conn.commit()
        return cur.rowcount

    def execute(self, sql: str, params: tuple = ()) -> list[dict]:
        """Execute raw SQL and return results as a list of dicts.

        Columns are NOT auto-decrypted in raw queries. Use this for
        administrative queries, aggregates, or custom joins.

        Args:
            sql: SQL statement to execute.
            params: Optional parameterized query values.

        Returns:
            List of dicts for SELECT statements; empty list for DML.
        """
        conn = self._require_conn()
        logger.debug("execute: %s", sql[:100])
        cur = conn.execute(sql, params)
        if cur.description:
            return [dict(row) for row in cur.fetchall()]
        conn.commit()
        return []
