"""
Database migration script to add missing columns to the subscriptions table.
Run this once to update your existing database.
"""
import sqlite3

DATABASE = 'marketing_panel.db'

def migrate():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("Starting database migration...")

    # Get current columns
    cursor.execute('PRAGMA table_info(subscriptions)')
    existing_columns = {row[1] for row in cursor.fetchall()}

    # Add missing columns
    columns_to_add = [
        ('plan_id', 'TEXT'),
        ('billing_period', 'TEXT'),
        ('message_limit', 'INTEGER'),
        ('usage_type', 'TEXT'),
        ('allowance_period', 'TEXT'),
        ('created_at', 'TEXT DEFAULT CURRENT_TIMESTAMP')
    ]

    for column_name, column_type in columns_to_add:
        if column_name not in existing_columns:
            try:
                cursor.execute(f'ALTER TABLE subscriptions ADD COLUMN {column_name} {column_type}')
                print(f"[OK] Added column: {column_name}")
            except sqlite3.OperationalError as e:
                print(f"[ERROR] Error adding {column_name}: {e}")
        else:
            print(f"- Column already exists: {column_name}")

    conn.commit()

    # Verify final schema
    print("\nFinal schema:")
    cursor.execute('PRAGMA table_info(subscriptions)')
    for row in cursor.fetchall():
        print(f"  {row[1]}: {row[2]}")

    conn.close()
    print("\nMigration complete!")

if __name__ == '__main__':
    migrate()
