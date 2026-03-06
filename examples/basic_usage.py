"""Basic sqlite-vault usage — encrypted contacts database.

Demonstrates:
- Defining a schema with EncryptedField and PlainField
- Inserting records with transparent encryption
- Querying with WHERE on plain fields
- Proving ciphertext is on disk (not plaintext)
"""

import os
import sqlite3

from sqlite_vault import EncryptedField, PlainField, VaultDB

schema = {
    "contacts": {
        "name": EncryptedField(),
        "email": EncryptedField(),
        "phone": EncryptedField(),
        "category": PlainField(),
        "created_at": PlainField(dtype="TEXT"),
    }
}

db_path = "/tmp/contacts_demo.db"

# Remove any leftover demo file
if os.path.exists(db_path):
    os.remove(db_path)

print("=== sqlite-vault basic usage ===\n")

with VaultDB(db_path, password="demo-password") as db:
    db.create_tables(schema)

    # Insert contacts
    db.insert(
        "contacts",
        name="Alice Smith",
        email="alice@example.com",
        phone="555-0100",
        category="work",
        created_at="2026-01-15",
    )
    db.insert(
        "contacts",
        name="Bob Jones",
        email="bob@example.com",
        phone="555-0200",
        category="personal",
        created_at="2026-02-20",
    )
    db.insert(
        "contacts",
        name="Carol White",
        email="carol@example.com",
        phone="555-0300",
        category="work",
        created_at="2026-03-01",
    )

    # Query — values are auto-decrypted
    print("Work contacts (auto-decrypted):")
    work = db.query("contacts", where={"category": "work"}, order_by="created_at ASC")
    for c in work:
        print(f"  {c['name']} — {c['email']} — {c['phone']}")

    print()

    # Update — encrypted fields re-encrypted automatically
    db.update("contacts", where={"category": "personal"}, phone="555-0999")
    updated = db.query("contacts", where={"category": "personal"})
    print(f"Bob's updated phone: {updated[0]['phone']}")

    print()

    # Delete
    deleted = db.delete("contacts", where={"category": "personal"})
    print(f"Deleted {deleted} personal contact(s)")

    remaining = db.query("contacts")
    print(f"Remaining contacts: {len(remaining)}")

# Prove that the data is encrypted on disk
print("\n=== What's stored on disk ===")
raw_conn = sqlite3.connect(db_path)
rows = raw_conn.execute("SELECT name, email, phone, category FROM contacts").fetchall()
raw_conn.close()

for row in rows:
    print(f"  name   (raw): {row[0][:60]}...")
    print(f"  email  (raw): {row[1][:60]}...")
    print(f"  phone  (raw): {row[2][:60]}...")
    print(f"  category (plain): {row[3]}")
    print()

print("(name/email/phone are Fernet ciphertext — not readable without the key)")

# Clean up
os.remove(db_path)
