import sqlite3
import json
import os
import base64
import hashlib
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

DATABASE = 'marketing_panel.db'

# Token Encryption Functions
def _get_encryption_key():
    """Derive a Fernet key from SECRET_KEY."""
    secret_key = os.getenv('SECRET_KEY', 'fallback-secret-key')
    # Fernet requires a 32-byte base64-encoded key
    # We use SHA256 to get a consistent 32-byte hash from SECRET_KEY
    key_hash = hashlib.sha256(secret_key.encode()).digest()
    return base64.urlsafe_b64encode(key_hash)

def encrypt_token(plain_token):
    """Encrypt a Discord token for secure storage."""
    if not plain_token:
        return None
    try:
        fernet = Fernet(_get_encryption_key())
        encrypted = fernet.encrypt(plain_token.encode())
        return encrypted.decode()  # Store as string in database
    except Exception as e:
        print(f"[ENCRYPTION ERROR] Failed to encrypt token: {e}")
        return None

def decrypt_token(encrypted_token):
    """Decrypt a Discord token when needed for API calls."""
    if not encrypted_token:
        return None
    try:
        fernet = Fernet(_get_encryption_key())
        decrypted = fernet.decrypt(encrypted_token.encode())
        return decrypted.decode()
    except Exception as e:
        print(f"[DECRYPTION ERROR] Failed to decrypt token: {e}")
        return None

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
            flagged INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Add flagged column if it doesn't exist (migration)
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN flagged INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Add flag_reason column if it doesn't exist (migration)
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN flag_reason TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Add flagged_at column if it doesn't exist (migration)
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN flagged_at TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Add session_id column if it doesn't exist (migration for session management)
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN session_id TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists

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
            all_time_sent INTEGER DEFAULT 0,
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

    # Business teams table (for business plan team management)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS business_teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_user_id INTEGER NOT NULL,
            subscription_id INTEGER NOT NULL,
            team_message TEXT,
            max_members INTEGER DEFAULT 3,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_user_id) REFERENCES users(id),
            FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
        )
    ''')

    # Business team members table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS business_team_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER NOT NULL,
            member_discord_id TEXT NOT NULL,
            member_username TEXT,
            member_avatar TEXT,
            invitation_status TEXT DEFAULT 'pending',
            added_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (team_id) REFERENCES business_teams(id),
            UNIQUE(team_id, member_discord_id)
        )
    ''')

    # Migration: Add message_delay column if it doesn't exist
    cursor.execute("PRAGMA table_info(user_data)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'message_delay' not in columns:
        cursor.execute('ALTER TABLE user_data ADD COLUMN message_delay INTEGER DEFAULT 1000')

    # Migration: Add all_time_sent column if it doesn't exist
    cursor.execute("PRAGMA table_info(usage)")
    usage_columns = [column[1] for column in cursor.fetchall()]
    if 'all_time_sent' not in usage_columns:
        cursor.execute('ALTER TABLE usage ADD COLUMN all_time_sent INTEGER DEFAULT 0')
        # Initialize all_time_sent with current messages_sent values
        cursor.execute('UPDATE usage SET all_time_sent = messages_sent WHERE all_time_sent = 0')

    # Migration: Add business usage tracking columns
    if 'business_messages_sent' not in usage_columns:
        cursor.execute('ALTER TABLE usage ADD COLUMN business_messages_sent INTEGER DEFAULT 0')
    if 'business_all_time_sent' not in usage_columns:
        cursor.execute('ALTER TABLE usage ADD COLUMN business_all_time_sent INTEGER DEFAULT 0')
    if 'business_last_reset' not in usage_columns:
        cursor.execute('ALTER TABLE usage ADD COLUMN business_last_reset TEXT')

    # Migration: Add business_selected_channels to user_data
    cursor.execute("PRAGMA table_info(user_data)")
    user_data_columns = [column[1] for column in cursor.fetchall()]
    if 'business_selected_channels' not in user_data_columns:
        cursor.execute('ALTER TABLE user_data ADD COLUMN business_selected_channels TEXT')

    # Migration: Add invitation_status to business_team_members
    cursor.execute("PRAGMA table_info(business_team_members)")
    team_members_columns = [column[1] for column in cursor.fetchall()]
    if 'invitation_status' not in team_members_columns:
        cursor.execute("ALTER TABLE business_team_members ADD COLUMN invitation_status TEXT DEFAULT 'pending'")
        # Set existing members to 'accepted' status
        cursor.execute("UPDATE business_team_members SET invitation_status = 'accepted' WHERE invitation_status IS NULL")

    # Note: max_members is set when business team is created
    # Changing config.py values won't affect existing teams to preserve user data

    conn.commit()
    conn.close()

def create_user(discord_id, username, avatar, discord_token, signup_ip):
    conn = get_db()
    cursor = conn.cursor()

    signup_date = datetime.now().isoformat()

    # Encrypt the token before storing
    encrypted_token = encrypt_token(discord_token)
    if not encrypted_token:
        print(f"[ERROR] Failed to encrypt token for user {discord_id}")
        return None

    try:
        cursor.execute('''
            INSERT INTO users (discord_id, username, avatar, discord_token, signup_ip, signup_date)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (discord_id, username, avatar, encrypted_token, signup_ip, signup_date))

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

def get_decrypted_token(discord_id):
    """Get and decrypt the user's Discord token for API calls.
    This should only be called when actually sending messages."""
    user = get_user_by_discord_id(discord_id)
    if not user:
        return None
    encrypted_token = user.get('discord_token')
    return decrypt_token(encrypted_token)

def get_user_by_id(user_id):
    """Get user by internal user ID (for admin panel)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def update_user_token(discord_id, discord_token):
    conn = get_db()
    cursor = conn.cursor()
    # Encrypt the token before storing
    encrypted_token = encrypt_token(discord_token)
    if not encrypted_token:
        print(f"[ERROR] Failed to encrypt token for user {discord_id}")
        conn.close()
        return False
    cursor.execute('UPDATE users SET discord_token = ? WHERE discord_id = ?', (encrypted_token, discord_id))
    conn.commit()
    conn.close()
    return True

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

            # Build query safely - update_parts are hardcoded column names, not user input
            query = f'UPDATE user_data SET {", ".join(update_parts)} WHERE user_id = ?'
            cursor.execute(query, params)
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
    """
    Permanently delete a user and ALL their data.
    This ensures complete removal with no recovery possible.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Get user_id first
    cursor.execute('SELECT id FROM users WHERE discord_id = ?', (discord_id,))
    user = cursor.fetchone()

    if user:
        user_id = user[0]

        # Delete business team if user owns one
        cursor.execute('SELECT id FROM business_teams WHERE owner_user_id = ?', (user_id,))
        team = cursor.fetchone()
        if team:
            team_id = team[0]
            # Delete all team members first
            cursor.execute('DELETE FROM business_team_members WHERE team_id = ?', (team_id,))
            # Delete the team
            cursor.execute('DELETE FROM business_teams WHERE id = ?', (team_id,))

        # Remove user from any business teams they're a member of
        cursor.execute('DELETE FROM business_team_members WHERE member_discord_id = ?', (discord_id,))

        # Delete all subscriptions
        cursor.execute('DELETE FROM subscriptions WHERE user_id = ?', (user_id,))

        # Delete all usage data
        cursor.execute('DELETE FROM usage WHERE user_id = ?', (user_id,))

        # Delete all user data (saved channels, drafts, etc.)
        cursor.execute('DELETE FROM user_data WHERE user_id = ?', (user_id,))

        # Finally delete the user record (includes encrypted token)
        cursor.execute('DELETE FROM users WHERE discord_id = ?', (discord_id,))

        conn.commit()

        # Run VACUUM to permanently remove deleted data from database file
        # This ensures data cannot be recovered from disk
        cursor.execute('VACUUM')

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

    # Update last_reset timestamp but preserve messages_sent count
    # This ensures that changing plans doesn't reset user's usage progress
    cursor.execute('''
        UPDATE usage SET last_reset = ? WHERE user_id = ?
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
    cursor.execute('UPDATE usage SET messages_sent = messages_sent + 1, all_time_sent = all_time_sent + 1 WHERE user_id = ?', (user_id,))
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
        usage = get_usage(user_id)
        all_time_sent = usage['all_time_sent'] if usage else 0
        return {
            'has_plan': False,
            'plan_name': 'No Plan',
            'message_limit': 0,
            'messages_sent': 0,
            'all_time_sent': all_time_sent,
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
            usage = get_usage(user_id)
            all_time_sent = usage['all_time_sent'] if usage else 0
            return {
                'has_plan': False,
                'plan_name': 'Expired',
                'message_limit': 0,
                'messages_sent': 0,
                'all_time_sent': all_time_sent,
                'messages_remaining': 0,
                'is_unlimited': False,
                'expires_at': None,
                'next_reset': None
            }

    # Check and reset allowance if needed
    check_and_reset_allowance(user_id, subscription)

    usage = get_usage(user_id)
    messages_sent = usage['messages_sent'] if usage else 0
    all_time_sent = usage['all_time_sent'] if usage else 0

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
        'all_time_sent': all_time_sent,
        'messages_remaining': remaining,
        'is_unlimited': is_unlimited,
        'usage_type': subscription['usage_type'],
        'allowance_period': subscription['allowance_period'],
        'expires_at': subscription['end_date'],
        'started_at': subscription['start_date'],
        'next_reset': next_reset
    }

def get_business_plan_status(team_id, owner_user_id):
    """
    Get business plan status with aggregated team member usage.
    Shows total usage across all team members for business plans.
    """
    # Get the base plan status from the owner
    plan_status = get_plan_status(owner_user_id)

    if not plan_status['has_plan']:
        return plan_status

    # Get all team member stats
    conn = get_db()
    cursor = conn.cursor()

    # Get owner's user_id for the team query
    cursor.execute('''
        SELECT btm.member_discord_id
        FROM business_team_members btm
        WHERE btm.team_id = ?
    ''', (team_id,))
    member_discord_ids = [row[0] for row in cursor.fetchall()]

    # Also include the owner's Discord ID
    cursor.execute('SELECT discord_id FROM users WHERE id = ?', (owner_user_id,))
    owner_row = cursor.fetchone()
    if owner_row:
        member_discord_ids.append(owner_row[0])

    # Get total business usage across all team members
    total_business_all_time = 0
    total_business_messages_sent = 0

    for discord_id in member_discord_ids:
        cursor.execute('SELECT id FROM users WHERE discord_id = ?', (discord_id,))
        user_row = cursor.fetchone()
        if user_row:
            user_id = user_row[0]
            cursor.execute('''
                SELECT business_all_time_sent, business_messages_sent
                FROM usage
                WHERE user_id = ?
            ''', (user_id,))
            usage_row = cursor.fetchone()
            if usage_row:
                total_business_all_time += usage_row[0] or 0
                total_business_messages_sent += usage_row[1] or 0

    conn.close()

    # Update plan status with aggregated business usage
    plan_status['all_time_sent'] = total_business_all_time
    plan_status['messages_sent'] = total_business_messages_sent

    # Recalculate remaining messages
    if plan_status['is_unlimited']:
        plan_status['messages_remaining'] = -1
    else:
        plan_status['messages_remaining'] = max(0, plan_status['message_limit'] - total_business_messages_sent)

    return plan_status

# Business team management functions

def create_business_team(owner_user_id, subscription_id, max_members=3):
    """Create a new business team for a business plan holder."""
    conn = get_db()
    cursor = conn.cursor()

    # Check if team already exists for this subscription
    cursor.execute('SELECT id FROM business_teams WHERE subscription_id = ?', (subscription_id,))
    existing = cursor.fetchone()

    if existing:
        conn.close()
        return existing[0]

    cursor.execute('''
        INSERT INTO business_teams (owner_user_id, subscription_id, max_members, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (owner_user_id, subscription_id, max_members, datetime.now().isoformat(), datetime.now().isoformat()))

    team_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return team_id

def get_business_team_by_owner(user_id):
    """Get business team where user is the owner."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT bt.* FROM business_teams bt
        JOIN subscriptions s ON bt.subscription_id = s.id
        WHERE bt.owner_user_id = ? AND s.is_active = 1
        ORDER BY bt.id DESC LIMIT 1
    ''', (user_id,))
    team = cursor.fetchone()
    conn.close()
    return dict(team) if team else None

def get_business_team_by_member(discord_id):
    """Get business team where user is a member."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT bt.* FROM business_teams bt
        JOIN business_team_members btm ON bt.id = btm.team_id
        WHERE btm.member_discord_id = ?
        ORDER BY bt.id DESC LIMIT 1
    ''', (discord_id,))
    team = cursor.fetchone()
    conn.close()
    return dict(team) if team else None

def add_team_member(team_id, discord_id, username, avatar):
    """Add a member to a business team with pending invitation status."""
    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO business_team_members (team_id, member_discord_id, member_username, member_avatar, invitation_status, added_at)
            VALUES (?, ?, ?, ?, 'pending', ?)
        ''', (team_id, discord_id, username, avatar, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False  # Member already exists

def remove_team_member(team_id, discord_id):
    """Remove a member from a business team."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM business_team_members WHERE team_id = ? AND member_discord_id = ?', (team_id, discord_id))
    conn.commit()
    conn.close()

def update_team_member_info(team_id, discord_id, username, avatar):
    """Update username and avatar for a team member."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE business_team_members
        SET member_username = ?, member_avatar = ?
        WHERE team_id = ? AND member_discord_id = ?
    ''', (username, avatar, team_id, discord_id))
    conn.commit()
    conn.close()

def update_user_profile(user_id, username, avatar):
    """Update username and avatar for a user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users
        SET username = ?, avatar = ?
        WHERE id = ?
    ''', (username, avatar, user_id))
    conn.commit()
    conn.close()

def get_team_members(team_id):
    """Get all members of a business team."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT btm.*, u.id as user_id
        FROM business_team_members btm
        LEFT JOIN users u ON u.discord_id = btm.member_discord_id
        WHERE btm.team_id = ?
        ORDER BY btm.added_at
    ''', (team_id,))
    members = cursor.fetchall()
    conn.close()
    return [dict(member) for member in members]

def get_team_member_count(team_id):
    """Get the count of active team members (accepted invitations only)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT COUNT(*) FROM business_team_members
        WHERE team_id = ? AND invitation_status = 'accepted'
    ''', (team_id,))
    count = cursor.fetchone()[0]
    conn.close()
    return count

def update_team_message(team_id, message):
    """Update the team message for a business team."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE business_teams SET team_message = ?, updated_at = ? WHERE id = ?
    ''', (message, datetime.now().isoformat(), team_id))
    conn.commit()
    conn.close()

def is_business_plan_owner(user_id):
    """Check if user is a business plan owner."""
    team = get_business_team_by_owner(user_id)
    return team is not None

def is_business_team_member(discord_id):
    """Check if user is a business team member."""
    team = get_business_team_by_member(discord_id)
    return team is not None

def get_team_member_stats(team_id):
    """Get statistics for all team members including their business usage."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT
            btm.member_discord_id,
            btm.member_username,
            btm.member_avatar,
            btm.added_at,
            u.id as user_id
        FROM business_team_members btm
        LEFT JOIN users u ON u.discord_id = btm.member_discord_id
        WHERE btm.team_id = ?
        ORDER BY btm.added_at
    ''', (team_id,))
    members = cursor.fetchall()

    stats = []
    for member in members:
        member_dict = dict(member)

        # Get business usage for this member if they have a user account
        if member_dict['user_id']:
            cursor.execute('''
                SELECT business_messages_sent, business_all_time_sent
                FROM usage
                WHERE user_id = ?
            ''', (member_dict['user_id'],))
            usage = cursor.fetchone()

            if usage:
                member_dict['business_messages_sent'] = usage[0] or 0
                member_dict['business_all_time_sent'] = usage[1] or 0
            else:
                member_dict['business_messages_sent'] = 0
                member_dict['business_all_time_sent'] = 0
        else:
            member_dict['business_messages_sent'] = 0
            member_dict['business_all_time_sent'] = 0

        stats.append(member_dict)

    conn.close()
    return stats


# Team invitation management functions

def get_team_invitations(discord_id):
    """Get all pending team invitations for a user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT btm.*, bt.owner_user_id, u.username as owner_username, u.avatar as owner_avatar, u.discord_id as owner_discord_id
        FROM business_team_members btm
        JOIN business_teams bt ON btm.team_id = bt.id
        JOIN users u ON bt.owner_user_id = u.id
        WHERE btm.member_discord_id = ? AND btm.invitation_status = 'pending'
        ORDER BY btm.added_at DESC
    ''', (discord_id,))
    invitations = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return invitations


def accept_team_invitation(member_id):
    """Accept a team invitation."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE business_team_members
        SET invitation_status = 'accepted'
        WHERE id = ?
    ''', (member_id,))
    conn.commit()
    conn.close()


def deny_team_invitation(member_id):
    """Deny a team invitation."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE business_team_members
        SET invitation_status = 'denied'
        WHERE id = ?
    ''', (member_id,))
    conn.commit()
    conn.close()


def clear_all_invitations(discord_id):
    """Clear all pending invitations for a user by marking them as denied."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE business_team_members
        SET invitation_status = 'denied'
        WHERE member_discord_id = ? AND invitation_status = 'pending'
    ''', (discord_id,))
    conn.commit()
    conn.close()


def leave_team(discord_id):
    """Leave a team by updating status to 'left'."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE business_team_members
        SET invitation_status = 'left'
        WHERE member_discord_id = ? AND invitation_status = 'accepted'
    ''', (discord_id,))
    conn.commit()
    conn.close()


def remove_team_member_from_list(member_id):
    """Remove a team member from the list (for denied/left members)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        DELETE FROM business_team_members
        WHERE id = ? AND invitation_status IN ('denied', 'left')
    ''', (member_id,))
    conn.commit()
    conn.close()


def get_current_team_for_member(discord_id):
    """Get the current team a member is part of (accepted status)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT bt.*, u.username as owner_username, u.discord_id as owner_discord_id
        FROM business_team_members btm
        JOIN business_teams bt ON btm.team_id = bt.id
        JOIN users u ON bt.owner_user_id = u.id
        WHERE btm.member_discord_id = ? AND btm.invitation_status = 'accepted'
        ORDER BY btm.added_at DESC LIMIT 1
    ''', (discord_id,))
    team = cursor.fetchone()
    conn.close()
    return dict(team) if team else None


# Admin Functions

def get_all_users_for_admin(filters=None):
    """Get all users with optional filters for admin panel."""
    conn = get_db()
    cursor = conn.cursor()

    query = '''
        SELECT u.*,
               (SELECT COUNT(*) FROM subscriptions WHERE user_id = u.id AND is_active = 1) as has_plan
        FROM users u
        WHERE 1=1
    '''

    params = []

    if filters:
        conditions = []
        if 'non_plan' in filters:
            conditions.append('(SELECT COUNT(*) FROM subscriptions WHERE user_id = u.id AND is_active = 1) = 0')
        if 'plan' in filters:
            conditions.append('(SELECT COUNT(*) FROM subscriptions WHERE user_id = u.id AND is_active = 1) > 0')
        if 'banned' in filters:
            conditions.append('u.banned = 1')
        if 'flagged' in filters:
            conditions.append('u.flagged = 1')

        if conditions:
            query += ' AND (' + ' OR '.join(conditions) + ')'

    query += ' ORDER BY u.created_at DESC'

    cursor.execute(query, params)
    users = [dict(row) for row in cursor.fetchall()]

    # Add is_admin flag for each user
    from admin_config import is_admin
    for user in users:
        user['is_admin'] = is_admin(user['discord_id'])

    conn.close()
    return users


def get_user_admin_details(user_id):
    """Get detailed user information for admin panel."""
    conn = get_db()
    cursor = conn.cursor()

    # Get user basic info
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    if not result:
        conn.close()
        return None

    user = dict(result)

    # Check if user is admin
    from admin_config import is_admin
    user['is_admin'] = is_admin(user['discord_id'])

    # Get active subscriptions
    cursor.execute('''
        SELECT * FROM subscriptions
        WHERE user_id = ? AND is_active = 1
    ''', (user_id,))
    user['subscriptions'] = [dict(row) for row in cursor.fetchall()]

    # Check if user is business team owner
    cursor.execute('''
        SELECT * FROM business_teams
        WHERE owner_user_id = ?
    ''', (user_id,))
    team = cursor.fetchone()
    user['is_business_owner'] = team is not None
    if team:
        user['business_team'] = dict(team)

    # Check if user is business team member
    cursor.execute('''
        SELECT bt.*, btm.member_discord_id
        FROM business_team_members btm
        JOIN business_teams bt ON btm.team_id = bt.id
        WHERE btm.member_discord_id = ? AND btm.invitation_status = 'accepted'
    ''', (user['discord_id'],))
    team_member = cursor.fetchone()
    user['is_business_member'] = team_member is not None
    if team_member:
        user['business_team_member_of'] = dict(team_member)
        # Get team owner info
        cursor.execute('SELECT * FROM users WHERE id = ?', (dict(team_member)['owner_user_id'],))
        owner = cursor.fetchone()
        if owner:
            user['business_team_owner'] = dict(owner)

    conn.close()
    return user


def ban_user(user_id):
    """Ban a user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET banned = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()


def unban_user(user_id):
    """Unban a user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET banned = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()


def flag_user(user_id, reason=None):
    """Flag a user for inappropriate content."""
    conn = get_db()
    cursor = conn.cursor()
    flagged_at = datetime.now().isoformat()
    cursor.execute('UPDATE users SET flagged = 1, flag_reason = ?, flagged_at = ? WHERE id = ?', (reason, flagged_at, user_id))
    conn.commit()
    conn.close()


def unflag_user(user_id):
    """Remove flag from a user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET flagged = 0, flag_reason = NULL, flagged_at = NULL WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()


def delete_user_account_admin(user_id):
    """Delete a user account (admin function)."""
    conn = get_db()
    cursor = conn.cursor()

    # Delete user's subscriptions
    cursor.execute('DELETE FROM subscriptions WHERE user_id = ?', (user_id,))

    # Delete user's business team if they own one
    cursor.execute('SELECT id FROM business_teams WHERE owner_user_id = ?', (user_id,))
    team = cursor.fetchone()
    if team:
        team_id = team[0]
        cursor.execute('DELETE FROM business_team_members WHERE team_id = ?', (team_id,))
        cursor.execute('DELETE FROM business_teams WHERE id = ?', (team_id,))

    # Get user's discord_id to remove from business teams
    cursor.execute('SELECT discord_id FROM users WHERE id = ?', (user_id,))
    user_row = cursor.fetchone()
    if user_row:
        cursor.execute('DELETE FROM business_team_members WHERE member_discord_id = ?', (user_row[0],))

    # Delete user's saved data
    cursor.execute('DELETE FROM user_data WHERE user_id = ?', (user_id,))

    # Delete usage tracking
    cursor.execute('DELETE FROM usage WHERE user_id = ?', (user_id,))

    # Finally delete the user
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))

    conn.commit()
    conn.close()


# Initialize database on import
init_db()
