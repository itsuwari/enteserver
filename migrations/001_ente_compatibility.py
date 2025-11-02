"""
Database migration script for Ente compatibility updates
Run this script to update existing database with new fields and tables
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from app.db import engine, Base
from app.models import User, OneTimeToken, SRPSession, FileShareLink

def check_column_exists(table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table"""
    inspector = inspect(engine)
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns

def check_table_exists(table_name: str) -> bool:
    """Check if a table exists"""
    inspector = inspect(engine)
    return table_name in inspector.get_table_names()

def migrate_user_table():
    """Add new fields to User table for Ente compatibility"""
    print("Migrating User table...")
    
    new_fields = [
        ('srp_user_id', 'VARCHAR'),
        ('kek_salt', 'VARCHAR'), 
        ('mem_limit', 'INTEGER DEFAULT 67108864'),
        ('ops_limit', 'INTEGER DEFAULT 3'),
        ('is_email_mfa_enabled', 'BOOLEAN DEFAULT FALSE')
    ]
    
    with engine.connect() as conn:
        for field_name, field_type in new_fields:
            if not check_column_exists('users', field_name):
                print(f"  Adding column: {field_name}")
                conn.execute(text(f"ALTER TABLE users ADD COLUMN {field_name} {field_type}"))
                conn.commit()
            else:
                print(f"  Column {field_name} already exists")

def create_new_tables():
    """Create new tables (OneTimeToken, SRPSession)"""
    print("Creating new tables...")
    
    if not check_table_exists('one_time_tokens'):
        print("  Creating one_time_tokens table")
    else:
        print("  Table one_time_tokens already exists")
        
    if not check_table_exists('srp_sessions'):
        print("  Creating srp_sessions table")  
    else:
        print("  Table srp_sessions already exists")
    
    # Create all tables (only creates missing ones)
    Base.metadata.create_all(bind=engine)


def migrate_file_share_links():
    """Ensure file_share_links table and schema exist"""
    print("Checking file_share_links table...")
    with engine.connect() as conn:
        if not check_table_exists('file_share_links'):
            print("  Creating file_share_links table")
            Base.metadata.create_all(bind=engine, tables=[FileShareLink.__table__])
            return
        print("  Table file_share_links already exists")
        if not check_column_exists('file_share_links', 'app'):
            print("  Adding column: app")
            conn.execute(text("ALTER TABLE file_share_links ADD COLUMN app VARCHAR NOT NULL DEFAULT 'photos'"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_file_share_links_app ON file_share_links (app)"))
            conn.commit()
        else:
            print("  Column app already exists")

def main():
    """Run all migrations"""
    print("Starting Ente compatibility migration...")
    print(f"Database URL: {engine.url}")
    
    try:
        # Step 1: Add new columns to User table
        migrate_user_table()
        
        # Step 2: Create new tables
        create_new_tables()

        # Step 3: Ensure file share link support
        migrate_file_share_links()
        
        print("\nMigration completed successfully!")
        print("\nNew features added:")
        print("- User.srp_user_id: SRP user identifier")
        print("- User.kek_salt: Key encryption key salt")
        print("- User.mem_limit: Argon2 memory limit")
        print("- User.ops_limit: Argon2 operations limit") 
        print("- User.is_email_mfa_enabled: Email MFA flag")
        print("- OneTimeToken table: For OTT email verification") 
        print("- SRPSession table: For SRP protocol sessions")
        print("- FileShareLink table: Public share links with app-specific URLs")
        
    except Exception as e:
        print(f"Migration failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
