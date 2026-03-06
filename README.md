# sqlite-vault

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

Transparent field-level encryption for SQLite with Keychain-backed keys.

## Why

SQLCipher encrypts the whole database. Sometimes you only need to encrypt specific fields — like names, emails, or notes — while keeping timestamps and IDs queryable for indexing and aggregation. `sqlite-vault` wraps SQLite with automatic Fernet encryption at the column level. Define your schema once with `EncryptedField` and `PlainField` descriptors, and all encrypt/decrypt happens transparently on every read and write.

## Install

```bash
git clone https://github.com/RedBeret/sqlite-vault.git
cd sqlite-vault
pip install -e .
```

## Quick Start

```python
from sqlite_vault import VaultDB, EncryptedField, PlainField

schema = {
    "users": {
        "name": EncryptedField(),
        "email": EncryptedField(),
        "role": PlainField(),
        "created_at": PlainField(dtype="TEXT"),
    }
}

with VaultDB("myapp.db", password="secret") as db:
    db.create_tables(schema)
    db.insert("users", name="Alice", email="alice@example.com",
               role="admin", created_at="2026-01-15")

    users = db.query("users", where={"role": "admin"})
    print(users[0]["name"])   # "Alice"  ← auto-decrypted
```

On disk, `name` and `email` are stored as Fernet ciphertext. `role` and `created_at` are plaintext — queryable directly with SQL.

## Key Storage Options

**macOS Keychain** — key generated once, stored securely in Keychain:
```python
with VaultDB("app.db", keychain_service="myapp-key") as db:
    ...
```

**Password-derived** — key derived from passphrase via PBKDF2 (cross-platform):
```python
with VaultDB("app.db", password="my-passphrase") as db:
    ...
```

**Custom backend** — implement `CryptoBackend` protocol for any key source:
```python
from sqlite_vault import PasswordCrypto
crypto = PasswordCrypto("passphrase")
with VaultDB("app.db", crypto=crypto) as db:
    ...
```

## API Reference

### `VaultDB(db_path, *, keychain_service=None, password=None, crypto=None)`

Context manager. Provide exactly one of `keychain_service`, `password`, or `crypto`.

| Method | Description |
|--------|-------------|
| `create_tables(schema)` | Create tables from schema dict |
| `insert(table, **kwargs)` → `int` | Insert row, returns rowid |
| `query(table, where=None, order_by=None, limit=None)` → `list[dict]` | Select rows |
| `update(table, where, **kwargs)` → `int` | Update matching rows, returns count |
| `delete(table, where)` → `int` | Delete matching rows, returns count |
| `execute(sql, params=())` → `list[dict]` | Raw SQL (no auto-decrypt) |

### `EncryptedField()`
Marks a column as encrypted. Stored as TEXT (Fernet ciphertext). Cannot be used in `where` filters.

### `PlainField(dtype="TEXT")`
Stores values as-is. Supports `TEXT`, `INTEGER`, `REAL`, `BLOB`. Use for columns you need to filter, sort, or aggregate.

### `PasswordCrypto(password)`
Cross-platform PBKDF2-derived Fernet backend. The same password always produces the same key (deterministic salt), so encrypted values persist across restarts.

### `KeychainCrypto(service_name)`
macOS Keychain backend. Auto-generates a random Fernet key on first use and stores it under `service_name`.

## Encryption Details

- **Algorithm:** Fernet (AES-128-CBC + HMAC-SHA256)
- **Key storage:** macOS Keychain (`security` CLI) or PBKDF2-derived from password
- **PBKDF2 iterations:** 480,000 (OWASP recommended minimum)
- **Deterministic salt:** `PasswordCrypto` derives its salt from the password itself, so the same password always produces the same key. This is intentional for persistent storage but means identical passwords across different databases share a key. For higher security, pass an explicit random salt and store it separately.
- **Null handling:** `None` values stored as SQL NULL, not encrypted
- **WAL mode:** enabled for concurrent-safe reads
- **SQL identifiers:** table and column names are validated against `[a-zA-Z_][a-zA-Z0-9_]*` to prevent injection

## Security Considerations

**What's protected:** values in `EncryptedField` columns
**What's not protected:** table names, column names, plain field values, row counts, query patterns
**Threat model:** protects sensitive field values from direct database file access (e.g., backup exfiltration, accidental logging)
**Not a substitute for:** full-disk encryption, access control, or TLS — use those too

## Comparison

| Approach | What's encrypted | Queryable | Key storage |
|----------|-----------------|-----------|-------------|
| sqlite-vault | Selected fields | Plain fields, IDs | Keychain / password |
| SQLCipher | Entire database | Only when open | Passphrase |
| Manual encryption | Whatever you encrypt | Only decrypted in memory | DIY |

## Examples

- [`examples/basic_usage.py`](examples/basic_usage.py) — encrypted contacts database
- [`examples/habits_tracker.py`](examples/habits_tracker.py) — encrypted habit log with date range queries

## License

MIT — see [LICENSE](LICENSE)
