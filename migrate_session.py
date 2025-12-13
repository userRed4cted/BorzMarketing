"""
Database migration script to add session_id column to users table.
Run this once to update your existing database for single session support.
"""
import sqlite3

DATABASE = 'marketing_panel.db'

def migrate():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("Starting session migration...")

    # Get current columns
    cursor.execute('PRAGMA table_info(users)')
    existing_columns = {row[1] for row in cursor.fetchall()}

    # Add session_id column if it doesn't exist
    if 'session_id' not in existing_columns:
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN session_id TEXT')
            print("[OK] Added column: session_id")
        except sqlite3.OperationalError as e:
            print(f"[ERROR] Error adding session_id: {e}")
    else:
        print("- Column already exists: session_id")

    conn.commit()

    # Verify final schema
    print("\nFinal schema:")
    cursor.execute('PRAGMA table_info(users)')
    for row in cursor.fetchall():
        print(f"  {row[1]}: {row[2]}")

    conn.close()
    print("\nMigration complete!")

if __name__ == '__main__':
    migrate()
