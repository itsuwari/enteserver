"""
Create tables required for photo metadata (file data) features.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text
from app.db import engine, Base
from app.models import FileDataEntry, CollectionShare, PublicCollectionLink


def check_table_exists(table_name: str) -> bool:
    inspector = inspect(engine)
    return table_name in inspector.get_table_names()


def ensure_updated_at_us_column():
    """
    Old experimental tables might miss the updated_at_us column.
    Ensure it exists before we depend on it.
    """
    inspector = inspect(engine)
    columns = {col["name"] for col in inspector.get_columns("file_data_entries")}
    if "updated_at_us" not in columns:
        with engine.connect() as conn:
            conn.execute(
                text(
                    "ALTER TABLE file_data_entries "
                    "ADD COLUMN updated_at_us BIGINT NOT NULL DEFAULT (strftime('%s','now') * 1000000)"
                )
            )
            conn.commit()


def create_file_data_entries_table():
    if check_table_exists("file_data_entries"):
        print("file_data_entries table already exists")
        ensure_updated_at_us_column()
        return

    print("Creating file_data_entries table")
    Base.metadata.create_all(bind=engine, tables=[FileDataEntry.__table__])


def ensure_public_collection_columns():
    if not check_table_exists("public_collection_links"):
        print("public_collection_links table missing, creating...")
        Base.metadata.create_all(bind=engine, tables=[PublicCollectionLink.__table__])
        return

    desired_columns = {
        "device_limit": "INTEGER DEFAULT 0",
        "enable_download": "BOOLEAN DEFAULT TRUE",
        "enable_join": "BOOLEAN DEFAULT FALSE",
        "enable_collect": "BOOLEAN DEFAULT FALSE",
        "nonce": "VARCHAR",
        "mem_limit": "INTEGER",
        "ops_limit": "INTEGER",
        "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        "updated_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    }
    inspector = inspect(engine)
    existing = {col["name"] for col in inspector.get_columns("public_collection_links")}
    with engine.connect() as conn:
        for column, ddl in desired_columns.items():
            if column not in existing:
                print(f"Adding column {column} to public_collection_links")
                conn.execute(text(f"ALTER TABLE public_collection_links ADD COLUMN {column} {ddl}"))
        conn.commit()


def create_collection_shares_table():
    inspector = inspect(engine)
    if check_table_exists("collection_shares"):
        print("collection_shares table already exists")
        existing = {col["name"] for col in inspector.get_columns("collection_shares")}
        desired = {
            "magic_metadata_header": "TEXT",
            "magic_metadata_data": "TEXT",
            "magic_metadata_version": "INTEGER",
        }
        with engine.connect() as conn:
            for column, ddl in desired.items():
                if column not in existing:
                    print(f"Adding column {column} to collection_shares")
                    conn.execute(text(f"ALTER TABLE collection_shares ADD COLUMN {column} {ddl}"))
            conn.commit()
        return
    print("Creating collection_shares table")
    Base.metadata.create_all(bind=engine, tables=[CollectionShare.__table__])


def main():
    print("Starting photo metadata migration...")
    create_file_data_entries_table()
    ensure_public_collection_columns()
    create_collection_shares_table()
    print("Photo metadata migration complete.")


if __name__ == "__main__":
    main()
