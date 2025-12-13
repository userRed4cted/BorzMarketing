"""
Database migration script to create user_data table.
Run this once to add the table for storing selected channels and draft messages.
"""
import sqlite3

DATABASE = 'marketing_panel.db'

def migrate():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("Starting user_data table migration...")

    # Check if table exists
    cursor.execute('''
        SELECT name FROM sqlite_master
        WHERE type='table' AND name='user_data'
    ''')

    if cursor.fetchone():
        print("- Table 'user_data' already exists")
    else:
        # Create user_data table
        try:
            cursor.execute('''
                CREATE TABLE user_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    selected_channels TEXT,
                    draft_message TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            conn.commit()
            print("[OK] Created table: user_data")
        except sqlite3.OperationalError as e:
            print(f"[ERROR] Error creating user_data table: {e}")

    # Verify final schema
    print("\nuser_data table schema:")
    cursor.execute('PRAGMA table_info(user_data)')
    for row in cursor.fetchall():
        print(f"  {row[1]}: {row[2]}")

    conn.close()
    print("\nMigration complete!")

if __name__ == '__main__':
    migrate()
