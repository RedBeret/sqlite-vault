"""Example: encrypted habit tracker using sqlite-vault.

Tracks daily habits with sensitive data (mood, notes) encrypted,
but dates stored as plain fields for range queries and aggregation.

Demonstrates:
- Mixed encrypted/plain schema for range-queryable encrypted data
- ORDER BY and LIMIT on plain fields
- Using raw execute() for aggregates alongside auto-decrypted queries
"""

import os
import random
from datetime import date, timedelta

from sqlite_vault import EncryptedField, PlainField, VaultDB

# Schema: dates are plain (queryable), everything personal is encrypted
SCHEMA = {
    "habits": {
        "log_date": PlainField(dtype="TEXT"),   # plain: needed for date ranges
        "mood": EncryptedField(),                # encrypted: personal
        "sleep_hours": EncryptedField(),         # encrypted: personal
        "exercise_min": EncryptedField(),        # encrypted: personal
        "notes": EncryptedField(),               # encrypted: personal
        "streak": PlainField(dtype="INTEGER"),   # plain: useful for aggregates
    }
}

DB_PATH = "/tmp/habits_demo.db"

if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

print("=== Encrypted Habit Tracker ===\n")

# Seed some demo data
moods = ["great", "good", "okay", "tired", "stressed"]
today = date.today()

with VaultDB(DB_PATH, password="my-habit-key") as db:
    db.create_tables(SCHEMA)

    # Insert 14 days of habit data
    for i in range(14):
        log_date = (today - timedelta(days=13 - i)).isoformat()
        db.insert(
            "habits",
            log_date=log_date,
            mood=random.choice(moods),
            sleep_hours=str(round(random.uniform(5.5, 9.0), 1)),
            exercise_min=str(random.randint(0, 90)),
            notes=f"Day {i + 1} notes — personal reflection",
            streak=i + 1,
        )

    # Query last 7 days — all encrypted fields auto-decrypted
    print("Last 7 days of habits (decrypted):")
    recent = db.query("habits", order_by="log_date DESC", limit=7)
    print(f"  {'Date':<12} {'Mood':<10} {'Sleep':<7} {'Exercise':<10} Streak")
    print(f"  {'-'*11} {'-'*9} {'-'*6} {'-'*9} {'-'*6}")
    for row in recent:
        print(
            f"  {row['log_date']:<12} {row['mood']:<10} "
            f"{row['sleep_hours']:<7} {row['exercise_min']:<10} {row['streak']}"
        )

    print()

    # Aggregate on plain field (streak) — no encryption needed
    streak_data = db.execute("SELECT MAX(streak) as best, AVG(streak) as avg FROM habits")
    print(f"Best streak: {streak_data[0]['best']} days")
    print(f"Avg streak:  {streak_data[0]['avg']:.1f} days")

    print()

    # Query a specific date range using plain log_date
    start = (today - timedelta(days=6)).isoformat()
    week_entries = db.execute(
        "SELECT log_date, streak FROM habits WHERE log_date >= ?", (start,)
    )
    print(f"Entries in last 7 days: {len(week_entries)}")

print("\n=== On-disk verification ===")
import sqlite3
conn = sqlite3.connect(DB_PATH)
row = conn.execute(
    "SELECT log_date, mood, sleep_hours, streak FROM habits LIMIT 1"
).fetchone()
conn.close()

print(f"  log_date (plain):       {row[0]}")
print(f"  mood     (encrypted):   {row[1][:50]}...")
print(f"  sleep_hours (encrypted):{row[2][:50]}...")
print(f"  streak   (plain):       {row[3]}")

os.remove(DB_PATH)
print("\nDone.")
