"""DDL generation for sqlite-vault schemas.

Translates a schema dict (mapping table names to field dicts) into SQLite
CREATE TABLE statements. Also provides helpers for identifying which columns
in a table require encryption/decryption.
"""

from .fields import EncryptedField, PlainField


def create_table_sql(table_name: str, fields: dict) -> str:
    """Generate a CREATE TABLE IF NOT EXISTS statement.

    Args:
        table_name: Name of the SQLite table.
        fields: Mapping of column name to field descriptor (EncryptedField or PlainField).

    Returns:
        CREATE TABLE SQL string (not yet executed).

    Example::

        sql = create_table_sql("users", {
            "name": EncryptedField(),
            "email": EncryptedField(),
            "role": PlainField(),
        })
        # "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, ...)"
    """
    if not fields:
        raise ValueError(f"Schema for table '{table_name}' must have at least one field")

    columns = ["id INTEGER PRIMARY KEY AUTOINCREMENT"]
    for col_name, field in fields.items():
        columns.append(f"{col_name} {field.sql_type}")

    column_defs = ",\n    ".join(columns)
    return f"CREATE TABLE IF NOT EXISTS {table_name} (\n    {column_defs}\n)"


def get_encrypted_columns(fields: dict) -> frozenset[str]:
    """Return the set of column names that use EncryptedField.

    Args:
        fields: Mapping of column name to field descriptor.

    Returns:
        Frozenset of column names that are encrypted.
    """
    return frozenset(
        name for name, field in fields.items() if isinstance(field, EncryptedField)
    )
