#!/usr/bin/env python3
"""
Quick script to reset all banned users to unbanned status.
Run this once to fix the database.
"""

import sqlite3

def reset_banned_users():
    conn = sqlite3.connect('marketing_panel.db')
    cursor = conn.cursor()

    # Get count of banned users
    cursor.execute('SELECT COUNT(*) FROM users WHERE banned = 1')
    count = cursor.fetchone()[0]

    print(f"Found {count} banned users")

    # Reset all banned users
    cursor.execute('UPDATE users SET banned = 0 WHERE banned = 1')
    conn.commit()

    print(f"Reset {count} users to unbanned status")

    conn.close()

if __name__ == '__main__':
    reset_banned_users()
    print("Done!")
