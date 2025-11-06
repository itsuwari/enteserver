"""
Add missing metadata tracking columns (thumbnail size and magic metadata counts).
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text  # noqa: E402

from app.db import engine  # noqa: E402


def ensure_column(table: str, column: str, ddl: str) -> None:
    inspector = inspect(engine)
    columns = {col["name"] for col in inspector.get_columns(table)}
    if column in columns:
        print(f"{table}.{column} already present")
        return
    with engine.connect() as conn:
        print(f"Adding {column} to {table}")
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
        conn.commit()


def main():
    ensure_column("files", "thumbnail_size", "INTEGER")
    ensure_column("files", "magic_metadata_count", "INTEGER")
    ensure_column("files", "pub_magic_metadata_count", "INTEGER")
    ensure_column("collections", "magic_metadata_count", "INTEGER")
    ensure_column("collections", "pub_magic_metadata_count", "INTEGER")
    ensure_column("collection_shares", "magic_metadata_count", "INTEGER")


if __name__ == "__main__":
    main()
