"""Tests for sqlite-vault.

All tests use PasswordCrypto("test-key") for deterministic, Keychain-free testing.
Test databases are created in pytest's tmp_path fixture.
"""

import sqlite3
from pathlib import Path

import pytest

from sqlite_vault import EncryptedField, PlainField, PasswordCrypto, VaultDB
from sqlite_vault.fields import EncryptedField as EF, PlainField as PF
from sqlite_vault.schema import create_table_sql, get_encrypted_columns, validate_identifier


# ── PasswordCrypto ─────────────────────────────────────────────────────────


def test_password_crypto_roundtrip():
    """Encrypt then decrypt returns the original plaintext."""
    crypto = PasswordCrypto("my-test-password")
    original = "Hello, World!"
    assert crypto.decrypt(crypto.encrypt(original)) == original


def test_password_crypto_different_passwords_produce_different_ciphertext():
    """Different passwords produce different ciphertext."""
    c1 = PasswordCrypto("password-one")
    c2 = PasswordCrypto("password-two")
    ciphertext = c1.encrypt("secret")
    with pytest.raises(Exception):
        c2.decrypt(ciphertext)


def test_password_crypto_empty_password_raises():
    with pytest.raises(ValueError, match="Password must not be empty"):
        PasswordCrypto("")


def test_password_crypto_same_password_consistent_key():
    """Same password always produces a consistent key (deterministic salt)."""
    c1 = PasswordCrypto("consistent")
    c2 = PasswordCrypto("consistent")
    plaintext = "test value"
    assert c2.decrypt(c1.encrypt(plaintext)) == plaintext


# ── EncryptedField ────────────────────────────────────────────────────────


def test_encrypted_field_sql_type():
    assert EncryptedField().sql_type == "TEXT"


def test_encrypted_field_to_db_produces_ciphertext():
    crypto = PasswordCrypto("test")
    field = EncryptedField()
    raw = "sensitive data"
    ciphertext = field.to_db(raw, crypto)
    assert ciphertext != raw
    assert len(ciphertext) > 20  # Fernet tokens are long


def test_encrypted_field_from_db_recovers_plaintext():
    crypto = PasswordCrypto("test")
    field = EncryptedField()
    original = "sensitive data"
    ciphertext = field.to_db(original, crypto)
    recovered = field.from_db(ciphertext, crypto)
    assert recovered == original


def test_encrypted_field_none_passthrough():
    crypto = PasswordCrypto("test")
    field = EncryptedField()
    assert field.to_db(None, crypto) is None
    assert field.from_db(None, crypto) is None


# ── PlainField ────────────────────────────────────────────────────────────


def test_plain_field_default_type():
    assert PlainField().sql_type == "TEXT"


def test_plain_field_custom_types():
    assert PlainField(dtype="INTEGER").sql_type == "INTEGER"
    assert PlainField(dtype="REAL").sql_type == "REAL"
    assert PlainField(dtype="BLOB").sql_type == "BLOB"


def test_plain_field_invalid_dtype():
    with pytest.raises(ValueError, match="Invalid dtype"):
        PlainField(dtype="JSONB")


def test_plain_field_passthrough():
    crypto = PasswordCrypto("test")
    field = PlainField()
    for value in ["hello", 42, None, 3.14]:
        assert field.to_db(value, crypto) == value
        assert field.from_db(value, crypto) == value


# ── Schema ────────────────────────────────────────────────────────────────


def test_create_table_sql_includes_columns():
    sql = create_table_sql("users", {
        "name": EncryptedField(),
        "role": PlainField(),
    })
    assert "CREATE TABLE IF NOT EXISTS users" in sql
    assert "name TEXT" in sql
    assert "role TEXT" in sql
    assert "id INTEGER PRIMARY KEY AUTOINCREMENT" in sql


def test_create_table_sql_empty_fields_raises():
    with pytest.raises(ValueError, match="at least one field"):
        create_table_sql("empty", {})


def test_get_encrypted_columns():
    fields = {
        "name": EncryptedField(),
        "email": EncryptedField(),
        "role": PlainField(),
    }
    enc = get_encrypted_columns(fields)
    assert enc == frozenset({"name", "email"})
    assert "role" not in enc


def test_validate_identifier_accepts_valid():
    assert validate_identifier("users") == "users"
    assert validate_identifier("_private") == "_private"
    assert validate_identifier("col_2") == "col_2"


def test_validate_identifier_rejects_injection():
    for bad in ["users; DROP TABLE", "col name", "1start", "a-b", "x'OR'1"]:
        with pytest.raises(ValueError, match="Invalid SQL identifier"):
            validate_identifier(bad)


# ── VaultDB context manager ───────────────────────────────────────────────


def test_vault_requires_context_manager(tmp_path):
    db = VaultDB(tmp_path / "test.db", password="test")
    with pytest.raises(RuntimeError, match="context manager"):
        db.insert("users", name="Alice")


def test_vault_context_manager_opens_and_closes(tmp_path):
    with VaultDB(tmp_path / "test.db", password="test") as db:
        assert db._conn is not None
    assert db._conn is None


def test_vault_exactly_one_crypto_arg(tmp_path):
    with pytest.raises(ValueError, match="exactly one"):
        VaultDB(tmp_path / "x.db")  # none provided

    with pytest.raises(ValueError, match="exactly one"):
        VaultDB(tmp_path / "x.db", password="a", keychain_service="b")  # two provided


# ── Full CRUD ─────────────────────────────────────────────────────────────


SCHEMA = {
    "contacts": {
        "name": EncryptedField(),
        "email": EncryptedField(),
        "category": PlainField(),
        "score": PlainField(dtype="INTEGER"),
    }
}


def make_db(tmp_path: Path) -> VaultDB:
    return VaultDB(tmp_path / "test.db", password="test-pass")


def test_insert_and_query(tmp_path):
    with make_db(tmp_path) as db:
        db.create_tables(SCHEMA)
        rowid = db.insert("contacts", name="Alice", email="alice@test.com", category="work", score=10)
        assert isinstance(rowid, int) and rowid > 0

        rows = db.query("contacts")
        assert len(rows) == 1
        assert rows[0]["name"] == "Alice"
        assert rows[0]["email"] == "alice@test.com"
        assert rows[0]["category"] == "work"


def test_query_with_where(tmp_path):
    with make_db(tmp_path) as db:
        db.create_tables(SCHEMA)
        db.insert("contacts", name="Alice", email="a@test.com", category="work", score=10)
        db.insert("contacts", name="Bob", email="b@test.com", category="personal", score=5)

        work = db.query("contacts", where={"category": "work"})
        assert len(work) == 1
        assert work[0]["name"] == "Alice"


def test_query_encrypted_where_raises(tmp_path):
    with make_db(tmp_path) as db:
        db.create_tables(SCHEMA)
        db.insert("contacts", name="Alice", email="a@test.com", category="work", score=10)

        with pytest.raises(ValueError, match="encrypted column"):
            db.query("contacts", where={"name": "Alice"})


def test_update(tmp_path):
    with make_db(tmp_path) as db:
        db.create_tables(SCHEMA)
        db.insert("contacts", name="Alice", email="a@test.com", category="work", score=10)

        updated = db.update("contacts", where={"category": "work"}, name="Alicia", score=20)
        assert updated == 1

        rows = db.query("contacts", where={"category": "work"})
        assert rows[0]["name"] == "Alicia"
        assert rows[0]["score"] == 20


def test_delete(tmp_path):
    with make_db(tmp_path) as db:
        db.create_tables(SCHEMA)
        db.insert("contacts", name="Alice", email="a@test.com", category="work", score=1)
        db.insert("contacts", name="Bob", email="b@test.com", category="work", score=2)

        deleted = db.delete("contacts", where={"category": "work"})
        assert deleted == 2
        assert db.query("contacts") == []


def test_encrypted_fields_are_ciphertext_on_disk(tmp_path):
    """Verify that encrypted columns store ciphertext, not plaintext, in SQLite."""
    db_path = tmp_path / "test.db"
    with VaultDB(db_path, password="secret") as db:
        db.create_tables(SCHEMA)
        db.insert("contacts", name="Alice", email="alice@private.com", category="work", score=1)

    # Open the DB with plain sqlite3 — should NOT see plaintext
    conn = sqlite3.connect(str(db_path))
    row = conn.execute("SELECT name, email FROM contacts LIMIT 1").fetchone()
    conn.close()

    assert row[0] != "Alice", "name should be encrypted on disk"
    assert "alice@private.com" not in row[1], "email should be encrypted on disk"
    # Fernet tokens start with 'g' (base64url gAAAAA...)
    assert len(row[0]) > 50, "Fernet ciphertext should be long"


def test_query_limit(tmp_path):
    with make_db(tmp_path) as db:
        db.create_tables(SCHEMA)
        for i in range(5):
            db.insert("contacts", name=f"User{i}", email=f"u{i}@test.com",
                      category="test", score=i)
        rows = db.query("contacts", limit=3)
        assert len(rows) == 3


def test_query_order_by(tmp_path):
    with make_db(tmp_path) as db:
        db.create_tables(SCHEMA)
        db.insert("contacts", name="Charlie", email="c@test.com", category="x", score=30)
        db.insert("contacts", name="Alice", email="a@test.com", category="x", score=10)
        db.insert("contacts", name="Bob", email="b@test.com", category="x", score=20)

        rows = db.query("contacts", order_by="score ASC")
        scores = [r["score"] for r in rows]
        assert scores == [10, 20, 30]


def test_execute_raw(tmp_path):
    with make_db(tmp_path) as db:
        db.create_tables(SCHEMA)
        db.insert("contacts", name="Alice", email="a@test.com", category="work", score=42)

        # Raw execute — values are NOT decrypted
        raw = db.execute("SELECT score FROM contacts WHERE category = ?", ("work",))
        assert raw[0]["score"] == 42  # plain field, same in raw
