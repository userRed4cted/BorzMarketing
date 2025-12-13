import sqlite3
import json
from datetime import datetime, timedelta

DATABASE = 'marketing_panel.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            avatar TEXT,
            discord_token TEXT NOT NULL,
            signup_ip TEXT NOT NULL,
            signup_date TEXT NOT NULL,
            banned INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Subscriptions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            plan_type TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            plan_name TEXT NOT NULL,
            billing_period TEXT,
            message_limit INTEGER,
            usage_type TEXT,
            allowance_period TEXT,
            start_date TEXT NOT NULL,
            end_date TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Usage tracking table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            messages_sent INTEGER DEFAULT 0,
            last_reset TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # User data table (for selected channels and draft messages)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            selected_channels TEXT,
            draft_message TEXT,
            message_delay INTEGER DEFAULT 1000,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Migration: Add message_delay column if it doesn't exist
    cursor.execute("PRAGMA table_info(user_data)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'message_delay' not in columns:
        cursor.execute('ALTER TABLE user_data ADD COLUMN message_delay INTEGER DEFAULT 1000')

    conn.commit()
    conn.close()

def create_user(discord_id, username, avatar, discord_token, signup_ip):
    conn = get_db()
    cursor = conn.cursor()

    signup_date = datetime.now().isoformat()

    try:
        cursor.execute('''
            INSERT INTO users (discord_id, username, avatar, discord_token, signup_ip, signup_date)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (discord_id, username, avatar, discord_token, signup_ip, signup_date))

        user_id = cursor.lastrowid

        # Initialize usage tracking
        cursor.execute('''
            INSERT INTO usage (user_id, messages_sent, last_reset)
            VALUES (?, 0, ?)
        ''', (user_id, datetime.now().isoformat()))

        conn.commit()
        return user_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def get_user_by_discord_id(discord_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE discord_id = ?', (discord_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def update_user_token(discord_id, discord_token):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET discord_token = ? WHERE discord_id = ?', (discord_token, discord_id))
    conn.commit()
    conn.close()

def update_user_session(discord_id, session_id):
    """Update the session ID for a user when they log in."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET session_id = ? WHERE discord_id = ?', (session_id, discord_id))
    conn.commit()
    conn.close()

def validate_user_session(discord_id, session_id):
    """Check if the provided session ID matches the stored session ID."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT session_id FROM users WHERE discord_id = ?', (discord_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return False

    stored_session_id = user[0] if user[0] else None
    return stored_session_id == session_id

def save_user_data(user_id, selected_channels=None, draft_message=None, message_delay=None):
    """Save or update user's selected channels, draft message, and message delay."""
    conn = get_db()
    cursor = conn.cursor()

    # Convert channels list to JSON string
    channels_json = json.dumps(selected_channels) if selected_channels is not None else None

    # Check if user_data exists
    cursor.execute('SELECT id FROM user_data WHERE user_id = ?', (user_id,))
    existing = cursor.fetchone()

    if existing:
        # Update existing record
        update_parts = []
        params = []

        if selected_channels is not None:
            update_parts.append('selected_channels = ?')
            params.append(channels_json)

        if draft_message is not None:
            update_parts.append('draft_message = ?')
            params.append(draft_message)

        if message_delay is not None:
            update_parts.append('message_delay = ?')
            params.append(message_delay)

        if update_parts:
            update_parts.append('updated_at = ?')
            params.append(datetime.now().isoformat())
            params.append(user_id)

            cursor.execute(f'''
                UPDATE user_data SET {', '.join(update_parts)}
                WHERE user_id = ?
            ''', params)
    else:
        # Insert new record
        cursor.execute('''
            INSERT INTO user_data (user_id, selected_channels, draft_message, message_delay, updated_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, channels_json, draft_message, message_delay if message_delay is not None else 1000, datetime.now().isoformat()))

    conn.commit()
    conn.close()

def get_user_data(user_id):
    """Get user's selected channels, draft message, and message delay."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT selected_channels, draft_message, message_delay FROM user_data WHERE user_id = ?', (user_id,))
    data = cursor.fetchone()
    conn.close()

    if not data:
        return {'selected_channels': [], 'draft_message': '', 'message_delay': 1000}

    # Parse JSON channels
    channels = json.loads(data[0]) if data[0] else []
    message = data[1] if data[1] else ''
    delay = data[2] if data[2] is not None else 1000

    return {
        'selected_channels': channels,
        'draft_message': message,
        'message_delay': delay
    }

def delete_user(discord_id):
    conn = get_db()
    cursor = conn.cursor()

    # Get user_id first
    cursor.execute('SELECT id FROM users WHERE discord_id = ?', (discord_id,))
    user = cursor.fetchone()

    if user:
        user_id = user[0]
        # Delete related records
        cursor.execute('DELETE FROM subscriptions WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM usage WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM user_data WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM users WHERE discord_id = ?', (discord_id,))
        conn.commit()

    conn.close()

def get_active_subscription(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM subscriptions
        WHERE user_id = ? AND is_active = 1
        ORDER BY id DESC LIMIT 1
    ''', (user_id,))
    sub = cursor.fetchone()
    conn.close()
    return dict(sub) if sub else None

def set_subscription(user_id, plan_type, plan_id, plan_config, billing_period=None):
    """
    Activate a subscription or one-time plan for a user.

    Args:
        user_id: User's database ID
        plan_type: 'subscription' or 'one-time'
        plan_id: Plan identifier from config
        plan_config: Plan configuration dict from config.py
        billing_period: 'monthly' or 'yearly' (for subscriptions only)
    """
    conn = get_db()
    cursor = conn.cursor()

    # Deactivate old subscriptions
    cursor.execute('UPDATE subscriptions SET is_active = 0 WHERE user_id = ?', (user_id,))

    # Calculate end date
    start_date = datetime.now()
    end_date = None

    if plan_type == 'subscription':
        # Subscriptions run until cancelled
        if billing_period == 'yearly':
            end_date = (start_date + timedelta(days=365)).isoformat()
        else:  # monthly
            end_date = (start_date + timedelta(days=30)).isoformat()
    else:  # one-time
        # One-time plans have specific duration
        duration_days = plan_config.get('duration_days', 1)
        end_date = (start_date + timedelta(days=duration_days)).isoformat()

    # Add new subscription
    cursor.execute('''
        INSERT INTO subscriptions (
            user_id, plan_type, plan_id, plan_name, billing_period,
            message_limit, usage_type, allowance_period,
            start_date, end_date, is_active
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    ''', (
        user_id,
        plan_type,
        plan_id,
        plan_config.get('name'),
        billing_period,
        plan_config.get('message_limit'),
        plan_config.get('usage_type'),
        plan_config.get('allowance_period'),
        start_date.isoformat(),
        end_date
    ))

    # Reset usage when activating a new plan
    cursor.execute('''
        UPDATE usage SET messages_sent = 0, last_reset = ? WHERE user_id = ?
    ''', (start_date.isoformat(), user_id))

    conn.commit()
    conn.close()

def cancel_subscription(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE subscriptions SET is_active = 0 WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def get_usage(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM usage WHERE user_id = ?', (user_id,))
    usage = cursor.fetchone()
    conn.close()
    return dict(usage) if usage else None

def increment_usage(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE usage SET messages_sent = messages_sent + 1 WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def reset_usage(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE usage SET messages_sent = 0, last_reset = ? WHERE user_id = ?
    ''', (datetime.now().isoformat(), user_id))
    conn.commit()
    conn.close()

def check_and_reset_allowance(user_id, subscription):
    """
    Check if allowance should be reset based on the plan's allowance_period.
    Returns True if reset was performed, False otherwise.
    """
    if not subscription or subscription['usage_type'] != 'allowance':
        return False

    usage = get_usage(user_id)
    if not usage or not usage['last_reset']:
        return False

    last_reset = datetime.fromisoformat(usage['last_reset'])
    now = datetime.now()
    allowance_period = subscription['allowance_period']

    should_reset = False

    if allowance_period == 'daily':
        # Reset if it's a new day
        should_reset = last_reset.date() < now.date()
    elif allowance_period == 'weekly':
        # Reset if it's a new week (Monday)
        last_week = last_reset.isocalendar()[1]
        current_week = now.isocalendar()[1]
        should_reset = last_week != current_week or last_reset.year != now.year
    elif allowance_period == 'monthly':
        # Reset if it's a new month
        should_reset = last_reset.month != now.month or last_reset.year != now.year

    if should_reset:
        reset_usage(user_id)
        return True

    return False

def can_send_message(user_id):
    """
    Check if user can send a message based on their plan and usage.
    Returns (can_send: bool, reason: str, remaining: int)
    """
    subscription = get_active_subscription(user_id)

    # No active subscription
    if not subscription:
        return False, "No active plan", 0

    # Check if plan has expired
    if subscription['end_date']:
        end_date = datetime.fromisoformat(subscription['end_date'])
        if datetime.now() > end_date:
            # Deactivate expired plan
            cancel_subscription(user_id)
            return False, "Plan expired", 0

    # Check and reset allowance if needed
    check_and_reset_allowance(user_id, subscription)

    # Unlimited messages
    if subscription['message_limit'] == -1:
        return True, "Unlimited", -1

    # Get current usage
    usage = get_usage(user_id)
    messages_sent = usage['messages_sent'] if usage else 0

    # Check if limit reached
    remaining = subscription['message_limit'] - messages_sent
    if remaining <= 0:
        return False, "Message limit reached", 0

    return True, "OK", remaining

def record_successful_send(user_id):
    """
    Record a successful message send. Only call this after a message is successfully sent.
    """
    increment_usage(user_id)

def get_plan_status(user_id):
    """
    Get comprehensive plan status for a user.
    Returns dict with plan info, usage, and limits.
    """
    subscription = get_active_subscription(user_id)

    if not subscription:
        return {
            'has_plan': False,
            'plan_name': 'No Plan',
            'message_limit': 0,
            'messages_sent': 0,
            'messages_remaining': 0,
            'is_unlimited': False,
            'expires_at': None,
            'next_reset': None
        }

    # Check if expired
    if subscription['end_date']:
        end_date = datetime.fromisoformat(subscription['end_date'])
        if datetime.now() > end_date:
            cancel_subscription(user_id)
            return {
                'has_plan': False,
                'plan_name': 'Expired',
                'message_limit': 0,
                'messages_sent': 0,
                'messages_remaining': 0,
                'is_unlimited': False,
                'expires_at': None,
                'next_reset': None
            }

    # Check and reset allowance if needed
    check_and_reset_allowance(user_id, subscription)

    usage = get_usage(user_id)
    messages_sent = usage['messages_sent'] if usage else 0

    is_unlimited = subscription['message_limit'] == -1
    remaining = -1 if is_unlimited else max(0, subscription['message_limit'] - messages_sent)

    # Calculate next reset time for allowance-based plans
    next_reset = None
    if subscription['usage_type'] == 'allowance' and usage and usage['last_reset']:
        last_reset = datetime.fromisoformat(usage['last_reset'])
        now = datetime.now()
        allowance_period = subscription['allowance_period']

        if allowance_period == 'daily':
            # Next reset is 24 hours after last reset
            next_reset = (last_reset + timedelta(days=1)).isoformat()
        elif allowance_period == 'weekly':
            # Next reset is 7 days after last reset
            next_reset = (last_reset + timedelta(weeks=1)).isoformat()
        elif allowance_period == 'monthly':
            # Next reset is 30 days after last reset
            next_reset = (last_reset + timedelta(days=30)).isoformat()

    return {
        'has_plan': True,
        'plan_type': subscription['plan_type'],
        'plan_id': subscription['plan_id'],
        'plan_name': subscription['plan_name'],
        'billing_period': subscription.get('billing_period'),
        'message_limit': subscription['message_limit'],
        'messages_sent': messages_sent,
        'messages_remaining': remaining,
        'is_unlimited': is_unlimited,
        'usage_type': subscription['usage_type'],
        'allowance_period': subscription['allowance_period'],
        'expires_at': subscription['end_date'],
        'started_at': subscription['start_date'],
        'next_reset': next_reset
    }

# Initialize database on import
init_db()
